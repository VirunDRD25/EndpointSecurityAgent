using System.Diagnostics;
using System.Text.RegularExpressions;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Reads Windows Firewall profile state.
/// Uses "netsh advfirewall show allprofiles state" which requires no extra
/// COM interop references and works reliably from a Windows Service context.
/// (Can be swapped for the HNetCfg.FwPolicy2 COM object later if you want
/// live event-driven notifications instead of polling.)
/// </summary>
public class FirewallChecker
{
    private readonly ILogger<FirewallChecker> _logger;

    public FirewallChecker(ILogger<FirewallChecker> logger)
    {
        _logger = logger;
    }

    public FirewallStatus Check()
    {
        var status = new FirewallStatus();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall show allprofiles state",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                _logger.LogWarning("Could not start netsh process to check firewall status");
                return status;
            }

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);

            var sections = Regex.Split(output, @"(?=Domain Profile Settings:|Private Profile Settings:|Public Profile Settings:)");

            foreach (var section in sections)
            {
                bool isOn = Regex.IsMatch(section, @"State\s+ON", RegexOptions.IgnoreCase);

                if (section.StartsWith("Domain", StringComparison.OrdinalIgnoreCase))
                    status.DomainEnabled = isOn;
                else if (section.StartsWith("Private", StringComparison.OrdinalIgnoreCase))
                    status.PrivateEnabled = isOn;
                else if (section.StartsWith("Public", StringComparison.OrdinalIgnoreCase))
                    status.PublicEnabled = isOn;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read firewall status");
        }

        return status;
    }
}
