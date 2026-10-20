using System.Diagnostics;
using System.Text.RegularExpressions;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Reads the currently connected Wi-Fi SSID via "netsh wlan show interfaces"
/// and compares it against the company's trusted SSID allowlist.
/// </summary>
public class WifiChecker
{
    private readonly ILogger<WifiChecker> _logger;
    private readonly AgentSettings _settings;

    public WifiChecker(ILogger<WifiChecker> logger, IOptions<AgentSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
    }

    public WifiStatus Check()
    {
        var status = new WifiStatus();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "wlan show interfaces",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                _logger.LogWarning("Could not start netsh to check Wi-Fi status");
                return status;
            }

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);

            var ssidMatch = Regex.Match(output, @"^\s*SSID\s*:\s*(.+)$", RegexOptions.Multiline);
            var signalMatch = Regex.Match(output, @"^\s*Signal\s*:\s*(\d+)%", RegexOptions.Multiline);

            if (ssidMatch.Success)
            {
                status.ConnectedSsid = ssidMatch.Groups[1].Value.Trim();
                status.IsTrusted = _settings.TrustedWifiSsids
                    .Any(trusted => string.Equals(trusted, status.ConnectedSsid, StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                status.ConnectedSsid = null; // not connected to Wi-Fi (e.g. on ethernet)
            }

            if (signalMatch.Success)
                status.SignalStrengthPercent = int.Parse(signalMatch.Groups[1].Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read Wi-Fi status");
        }

        return status;
    }
}
