using System.Management;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Reads BitLocker encryption status for the system (OS) drive via the
/// ROOT\CIMV2\Security\MicrosoftVolumeEncryption namespace.
/// NOTE: This namespace typically requires the agent process to run as
/// LocalSystem (i.e. as a Windows Service) — running as a normal user will
/// often fail with "Access Denied".
/// </summary>
public class BitLockerChecker
{
    private readonly ILogger<BitLockerChecker> _logger;

    public BitLockerChecker(ILogger<BitLockerChecker> logger)
    {
        _logger = logger;
    }

    public BitLockerStatus Check()
    {
        var status = new BitLockerStatus();

        try
        {
            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            systemDrive = systemDrive.TrimEnd('\\');

            var scope = new ManagementScope(@"root\CIMV2\Security\MicrosoftVolumeEncryption");
            var query = new ObjectQuery($"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '{systemDrive}'");
            using var searcher = new ManagementObjectSearcher(scope, query);

            foreach (ManagementObject obj in searcher.Get())
            {
                // ProtectionStatus: 0 = Unprotected, 1 = Protected, 2 = Unknown
                var protection = Convert.ToUInt32(obj["ProtectionStatus"] ?? 2u);
                status.ProtectionStatus = protection switch
                {
                    0 => "Unprotected",
                    1 => "Protected",
                    _ => "Unknown"
                };
                status.SystemDriveEncrypted = protection == 1;

                obj.InvokeMethod("GetConversionStatus", null); // primes properties on some builds

                try
                {
                    var inParams = obj.GetMethodParameters("GetConversionStatus");
                    var outParams = obj.InvokeMethod("GetConversionStatus", inParams, null);
                    if (outParams?["EncryptionPercentage"] != null)
                        status.EncryptionPercentage = Convert.ToInt32(outParams["EncryptionPercentage"]);
                }
                catch (Exception exInner)
                {
                    _logger.LogDebug(exInner, "GetConversionStatus not available, defaulting percentage");
                    status.EncryptionPercentage = status.SystemDriveEncrypted ? 100 : 0;
                }

                break;
            }
        }
        catch (ManagementException mex) when (mex.ErrorCode == ManagementStatus.NotFound)
        {
            _logger.LogWarning("BitLocker WMI provider not found — system drive may not have BitLocker available (e.g. Windows Home edition)");
        }
        catch (UnauthorizedAccessException uex)
        {
            _logger.LogError(uex, "Access denied reading BitLocker status. The agent must run as LocalSystem (Windows Service) for this check.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read BitLocker status");
        }

        return status;
    }
}
