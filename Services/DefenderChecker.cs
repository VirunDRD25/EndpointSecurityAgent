using System.Management;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Reads AV status — tries Defender's own WMI namespace first, then falls
/// back to root\SecurityCenter2 (AntiVirusProduct) so machines where a
/// 3rd-party AV (Avast, RAV, McAfee, etc.) has replaced Defender don't
/// falsely report "antivirus disabled".
/// </summary>
public class DefenderChecker
{
    private readonly ILogger<DefenderChecker> _logger;
    private const int UnknownSignatureAgeSentinel = 65535;

    public DefenderChecker(ILogger<DefenderChecker> logger)
    {
        _logger = logger;
    }

    public DefenderStatus Check()
    {
        var status = new DefenderStatus();

        try
        {
            var scope = new ManagementScope(@"root\Microsoft\Windows\Defender");
            var query = new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus");
            using var searcher = new ManagementObjectSearcher(scope, query);

            bool gotInstance = false;
            foreach (ManagementObject obj in searcher.Get())
            {
                gotInstance = true;
                status.StatusReadSuccessfully = true;

                status.AntivirusEnabled = Convert.ToBoolean(obj["AntivirusEnabled"] ?? false);
                status.RealTimeProtectionEnabled = Convert.ToBoolean(obj["RealTimeProtectionEnabled"] ?? false);

                var signatureAge = obj["AntivirusSignatureAge"];
                if (signatureAge == null)
                {
                    status.DefinitionsStatus = "Unknown";
                    status.DefinitionsUpToDate = true;
                    status.DefinitionAgeDays = -1;
                }
                else
                {
                    int age = Convert.ToInt32(signatureAge);
                    if (age == UnknownSignatureAgeSentinel)
                    {
                        status.DefinitionsStatus = "Unknown";
                        status.DefinitionsUpToDate = true;
                        status.DefinitionAgeDays = -1;
                        _logger.LogInformation("Defender signature age WMI sentinel (65535) — treating as Unknown.");
                    }
                    else
                    {
                        status.DefinitionAgeDays = age;
                        status.DefinitionsUpToDate = age <= 3;
                        status.DefinitionsStatus = status.DefinitionsUpToDate ? "UpToDate" : "Outdated";
                    }
                }

                var lastScan = obj["FullScanEndTime"]?.ToString();
                if (!string.IsNullOrEmpty(lastScan))
                {
                    try
                    {
                        status.LastFullScanUtc = ManagementDateTimeConverter.ToDateTime(lastScan).ToUniversalTime();
                    }
                    catch { }
                }

                break;
            }

            // Defender returned an instance but shows AV disabled —
            // means a 3rd-party AV (Avast, RAV, etc.) took over.
            // Check SecurityCenter2 before falsely flagging as unprotected.
            if (gotInstance && !status.AntivirusEnabled)
            {
                var thirdParty = GetSecurityCenterAv();
                if (thirdParty != null)
                {
                    _logger.LogInformation(
                        "Defender disabled but 3rd-party AV active: {Av} (state={State}). Treating as protected.",
                        thirdParty.Name, thirdParty.State);
                    status.AntivirusEnabled = true;
                    status.RealTimeProtectionEnabled = thirdParty.RealTimeEnabled;
                    status.DefinitionsStatus = "Unknown";
                    status.DefinitionsUpToDate = true;
                    status.DefinitionAgeDays = -1;
                }
            }

            if (!gotInstance)
            {
                _logger.LogWarning("MSFT_MpComputerStatus returned no instances — checking SecurityCenter2 fallback.");
                var thirdParty = GetSecurityCenterAv();
                if (thirdParty != null)
                {
                    status.StatusReadSuccessfully = true;
                    status.AntivirusEnabled = true;
                    status.RealTimeProtectionEnabled = thirdParty.RealTimeEnabled;
                    status.DefinitionsStatus = "Unknown";
                    status.DefinitionsUpToDate = true;
                    status.DefinitionAgeDays = -1;
                    _logger.LogInformation("SecurityCenter2 AV found: {Av}", thirdParty.Name);
                }
            }
        }
        catch (UnauthorizedAccessException uex)
        {
            _logger.LogError(uex,
                "Access denied reading Defender WMI. Run as Administrator or install as a Windows Service.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read Defender WMI — trying SecurityCenter2 fallback.");
            var thirdParty = GetSecurityCenterAv();
            if (thirdParty != null)
            {
                status.StatusReadSuccessfully = true;
                status.AntivirusEnabled = true;
                status.RealTimeProtectionEnabled = thirdParty.RealTimeEnabled;
                status.DefinitionsStatus = "Unknown";
                status.DefinitionsUpToDate = true;
                status.DefinitionAgeDays = -1;
            }
        }

        return status;
    }

    private record AvProduct(string Name, bool RealTimeEnabled, string State);

    /// <summary>
    /// Reads root\SecurityCenter2 AntiVirusProduct — works for any AV
    /// registered with Windows Security Center (Avast, McAfee, RAV, etc.).
    /// productState is a hex bitmask: bits 12-15 = real-time state (1 = on).
    /// </summary>
    private AvProduct? GetSecurityCenterAv()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT displayName, productState FROM AntiVirusProduct");

            foreach (ManagementObject obj in searcher.Get())
            {
                var name = obj["displayName"]?.ToString() ?? "Unknown AV";
                var productStateRaw = obj["productState"];
                if (productStateRaw == null) continue;

                uint productState = Convert.ToUInt32(productStateRaw);
                bool realTimeOn = ((productState >> 12) & 0xF) == 1;
                string state = realTimeOn ? "RealTimeOn" : "RealTimeOff";

                return new AvProduct(name, realTimeOn, state);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SecurityCenter2 query failed.");
        }
        return null;
    }
}