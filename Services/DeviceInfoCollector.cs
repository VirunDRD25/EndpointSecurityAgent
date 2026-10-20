using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Collects basic device / hardware / identity information.
/// A stable DeviceId is derived from the motherboard UUID so re-installs of
/// the agent still map to the same device record on the server.
/// </summary>
public class DeviceInfoCollector
{
    private readonly ILogger<DeviceInfoCollector> _logger;

    public DeviceInfoCollector(ILogger<DeviceInfoCollector> logger)
    {
        _logger = logger;
    }

    public void Populate(DeviceReport report)
    {
        try
        {
            report.DeviceName = Environment.MachineName;
            report.Username = $"{Environment.UserDomainName}\\{Environment.UserName}";
            report.WindowsVersion = GetWindowsVersionFriendlyName();
            report.SerialNumber = GetBiosSerialNumber();
            report.DeviceId = GetStableDeviceId();
            report.IpAddress = GetPrimaryIpAddress();
            report.MacAddress = GetPrimaryMacAddress();
            report.LastSeenUtc = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed collecting device info");
        }
    }

    private string GetStableDeviceId()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (var obj in searcher.Get())
            {
                var uuid = obj["UUID"]?.ToString();
                if (!string.IsNullOrWhiteSpace(uuid) && uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
                    return uuid;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read machine UUID, falling back to machine name");
        }

        return Environment.MachineName;
    }

    private string GetBiosSerialNumber()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
            foreach (var obj in searcher.Get())
            {
                return obj["SerialNumber"]?.ToString() ?? "Unknown";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read BIOS serial number");
        }
        return "Unknown";
    }

    private string GetWindowsVersionFriendlyName()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                var caption = obj["Caption"]?.ToString()?.Trim() ?? "Windows";
                var build = obj["BuildNumber"]?.ToString() ?? "";
                return $"{caption} (Build {build})";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read OS caption via WMI");
        }

        return Environment.OSVersion.VersionString;
    }

    private string GetPrimaryIpAddress()
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .FirstOrDefault(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork));

            var addr = nic?.GetIPProperties().UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            return addr?.ToString() ?? "Unknown";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not determine primary IP address");
            return "Unknown";
        }
    }

    private string GetPrimaryMacAddress()
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .FirstOrDefault(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork));

            var mac = nic?.GetPhysicalAddress()?.ToString();
            if (string.IsNullOrEmpty(mac)) return "Unknown";

            // Format as AA:BB:CC:DD:EE:FF
            return string.Join(":", Enumerable.Range(0, mac.Length / 2).Select(i => mac.Substring(i * 2, 2)));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not determine primary MAC address");
            return "Unknown";
        }
    }
}
