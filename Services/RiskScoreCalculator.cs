using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Combines every individual check into one 0-100 risk score plus a list of
/// human-readable reasons, so the dashboard can show "why" a device is risky.
/// </summary>
public class RiskScoreCalculator
{
    private readonly AgentSettings _settings;

    public RiskScoreCalculator(IOptions<AgentSettings> settings)
    {
        _settings = settings.Value;
    }

    public void Calculate(DeviceReport report)
    {
        int score = 0;
        var reasons = new List<string>();
        var w = _settings.RiskWeights;

        if (!report.Firewall.AllEnabled)
        {
            score += w.FirewallDisabled;
            reasons.Add("Firewall disabled on one or more network profiles");
        }

        if (!report.Defender.StatusReadSuccessfully)
        {
            // We could not read Defender status at all (usually a permissions
            // issue) — flag it as a data-quality issue, not "antivirus disabled",
            // so admins don't chase a false alarm.
            reasons.Add("Defender status could not be read (agent may need to run elevated/as a service)");
        }
        else
        {
            if (!report.Defender.AntivirusEnabled)
            {
                score += w.DefenderDisabled;
                reasons.Add("Microsoft Defender antivirus is disabled");
            }
            else if (!report.Defender.RealTimeProtectionEnabled)
            {
                score += w.RealtimeProtectionDisabled;
                reasons.Add("Real-time protection is disabled");
            }

            if (report.Defender.DefinitionsStatus == "Outdated")
            {
                score += w.DefinitionsOutdated;
                reasons.Add($"Virus definitions are {report.Defender.DefinitionAgeDays} day(s) old");
            }
            // DefinitionsStatus == "Unknown" (including the 65535 WMI sentinel)
            // is intentionally NOT scored — it's missing data, not a finding.
        }

        if (!report.BitLocker.SystemDriveEncrypted)
        {
            score += w.BitLockerOff;
            reasons.Add("BitLocker is not enabled on the system drive");
        }

        if (_settings.UsbPolicyBlocked && report.UsbEvents.Any(u => u.EventType == "Inserted"))
        {
            score += w.UnapprovedUsbConnected;
            reasons.Add("USB storage device connected (restricted by policy)");
        }

        if (report.UnauthorizedSoftware.Count > 0)
        {
            score += w.UnauthorizedSoftware;
            reasons.Add($"Unauthorized software detected: {string.Join(", ", report.UnauthorizedSoftware)}");
        }

        if (report.RecentDownloads.Any(d => d.IsSuspicious))
        {
            score += w.SuspiciousDownload;
            var names = string.Join(", ", report.RecentDownloads.Where(d => d.IsSuspicious).Select(d => d.FileName));
            reasons.Add($"Unsigned/suspicious executable(s) downloaded: {names}");
        }

        if (report.Wifi.ConnectedSsid != null && !report.Wifi.IsTrusted)
        {
            score += w.UntrustedWifi;
            reasons.Add($"Connected to untrusted Wi-Fi network: {report.Wifi.ConnectedSsid}");
        }

        if (report.WindowsUpdate.PendingUpdateCount > 0)
        {
            score += w.WindowsUpdatesPending;
            reasons.Add($"{report.WindowsUpdate.PendingUpdateCount} Windows update(s) pending");
        }

        if (!report.WindowsUpdate.IsSupportedVersion)
        {
            score += w.UnsupportedWindowsVersion;
            reasons.Add("Device is running an unsupported Windows version/build");
        }

        if (report.BrowserExtensions.Any(e => e.IsBlacklisted))
        {
            score += w.BlacklistedExtension;
            var names = string.Join(", ", report.BrowserExtensions.Where(e => e.IsBlacklisted).Select(e => e.Name).Distinct());
            reasons.Add($"Blacklisted browser extension(s) detected: {names}");
        }

        if (report.BrowserExtensions.Any(e => e.IsDeveloperMode))
        {
            score += w.DeveloperModeExtension;
            var names = string.Join(", ", report.BrowserExtensions.Where(e => e.IsDeveloperMode).Select(e => e.Name).Distinct());
            reasons.Add($"Developer-mode (unpacked) browser extension(s) detected: {names}");
        }

        if (report.BrowserExtensions.Any(e => e.Publisher == "Unknown"))
        {
            score += w.UnknownPublisherExtension;
            reasons.Add("Browser extension(s) from an unknown publisher detected");
        }

        if (report.BrowserExtensions.Any(e => e.HasDangerousPermissions))
        {
            score += w.DangerousExtensionPermissions;
            reasons.Add("Browser extension(s) requesting dangerous permissions detected");
        }

        if (report.MissingRequiredSecurityExtensions.Count > 0)
        {
            score += w.SecurityExtensionRemoved;
            reasons.Add($"Required security extension(s) missing: {string.Join(", ", report.MissingRequiredSecurityExtensions)}");
        }

        report.RiskScore = Math.Min(score, 100);
        report.RiskFactors = reasons;
    }
}
