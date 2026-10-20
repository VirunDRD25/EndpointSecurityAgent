using System.Text.Json.Serialization;

namespace EndpointSecurityAgent.Models;

/// <summary>
/// The full payload the agent POSTs to /api/device/report
/// </summary>
public class DeviceReport
{
    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("deviceName")]
    public string DeviceName { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("windowsVersion")]
    public string WindowsVersion { get; set; } = string.Empty;

    [JsonPropertyName("ipAddress")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("macAddress")]
    public string MacAddress { get; set; } = string.Empty;

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("lastSeenUtc")]
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("firewall")]
    public FirewallStatus Firewall { get; set; } = new();

    [JsonPropertyName("defender")]
    public DefenderStatus Defender { get; set; } = new();

    [JsonPropertyName("bitLocker")]
    public BitLockerStatus BitLocker { get; set; } = new();

    [JsonPropertyName("windowsUpdate")]
    public WindowsUpdateStatus WindowsUpdate { get; set; } = new();

    [JsonPropertyName("installedSoftware")]
    public List<string> InstalledSoftware { get; set; } = new();

    [JsonPropertyName("browserExtensions")]
    public List<BrowserExtensionInfo> BrowserExtensions { get; set; } = new();

    [JsonPropertyName("missingRequiredSecurityExtensions")]
    public List<string> MissingRequiredSecurityExtensions { get; set; } = new();

    [JsonPropertyName("unauthorizedSoftware")]
    public List<string> UnauthorizedSoftware { get; set; } = new();

    [JsonPropertyName("recentDownloads")]
    public List<DownloadedFileInfo> RecentDownloads { get; set; } = new();

    [JsonPropertyName("usbEvents")]
    public List<UsbEvent> UsbEvents { get; set; } = new();

    [JsonPropertyName("wifi")]
    public WifiStatus Wifi { get; set; } = new();

    [JsonPropertyName("fileRisks")]
    public List<FileRiskInfo> FileRisks { get; set; } = new();

    [JsonPropertyName("riskScore")]
    public int RiskScore { get; set; }

    [JsonPropertyName("riskFactors")]
    public List<string> RiskFactors { get; set; } = new();
}

public class FirewallStatus
{
    [JsonPropertyName("domainEnabled")]
    public bool DomainEnabled { get; set; }

    [JsonPropertyName("privateEnabled")]
    public bool PrivateEnabled { get; set; }

    [JsonPropertyName("publicEnabled")]
    public bool PublicEnabled { get; set; }

    [JsonIgnore]
    public bool AllEnabled => DomainEnabled && PrivateEnabled && PublicEnabled;
}

public class DefenderStatus
{
    [JsonPropertyName("antivirusEnabled")]
    public bool AntivirusEnabled { get; set; }

    [JsonPropertyName("realTimeProtectionEnabled")]
    public bool RealTimeProtectionEnabled { get; set; }

    [JsonPropertyName("definitionsUpToDate")]
    public bool DefinitionsUpToDate { get; set; }

    [JsonPropertyName("definitionAgeDays")]
    public int DefinitionAgeDays { get; set; }

    /// <summary>
    /// "UpToDate", "Outdated", or "Unknown" — WMI reports an age of 65535
    /// (uint16 sentinel) when Defender has never fully initialized/reported
    /// a value. "Unknown" must NOT be scored as risk since it isn't a real
    /// finding, just missing data.
    /// </summary>
    [JsonPropertyName("definitionsStatus")]
    public string DefinitionsStatus { get; set; } = "Unknown";

    [JsonPropertyName("lastFullScanUtc")]
    public DateTime? LastFullScanUtc { get; set; }

    /// <summary>True if the WMI query itself succeeded and returned a real instance.</summary>
    [JsonPropertyName("statusReadSuccessfully")]
    public bool StatusReadSuccessfully { get; set; }
}

public class BitLockerStatus
{
    [JsonPropertyName("systemDriveEncrypted")]
    public bool SystemDriveEncrypted { get; set; }

    [JsonPropertyName("protectionStatus")]
    public string ProtectionStatus { get; set; } = "Unknown";

    [JsonPropertyName("encryptionPercentage")]
    public int EncryptionPercentage { get; set; }
}

public class WindowsUpdateStatus
{
    [JsonPropertyName("lastInstalledUtc")]
    public DateTime? LastInstalledUtc { get; set; }

    [JsonPropertyName("pendingUpdateCount")]
    public int PendingUpdateCount { get; set; }

    [JsonPropertyName("isSupportedVersion")]
    public bool IsSupportedVersion { get; set; } = true;
}

public class DownloadedFileInfo
{
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("fullPath")]
    public string FullPath { get; set; } = string.Empty;

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [JsonPropertyName("isDigitallySigned")]
    public bool IsDigitallySigned { get; set; }

    [JsonPropertyName("publisher")]
    public string Publisher { get; set; } = "Unknown";

    [JsonPropertyName("fileType")]
    public string FileType { get; set; } = string.Empty;

    [JsonPropertyName("detectedUtc")]
    public DateTime DetectedUtc { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("sourceFolder")]
    public string SourceFolder { get; set; } = string.Empty;

    [JsonPropertyName("isSuspicious")]
    public bool IsSuspicious { get; set; }
}

public class UsbEvent
{
    [JsonPropertyName("deviceDescription")]
    public string DeviceDescription { get; set; } = string.Empty;

    [JsonPropertyName("driveLetter")]
    public string? DriveLetter { get; set; }

    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    [JsonPropertyName("insertedUtc")]
    public DateTime InsertedUtc { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = "Inserted"; // Inserted | Removed
}

public class WifiStatus
{
    [JsonPropertyName("connectedSsid")]
    public string? ConnectedSsid { get; set; }

    [JsonPropertyName("isTrusted")]
    public bool IsTrusted { get; set; }

    [JsonPropertyName("signalStrengthPercent")]
    public int SignalStrengthPercent { get; set; }
}

public class BrowserExtensionInfo
{
    [JsonPropertyName("browser")]
    public string Browser { get; set; } = string.Empty; // Chrome | Edge | Brave | Opera | Firefox

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = string.Empty; // "Default", "Profile 1", etc.

    [JsonPropertyName("extensionId")]
    public string ExtensionId { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = "Unknown";

    [JsonPropertyName("publisher")]
    public string Publisher { get; set; } = "Unknown";

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = new();

    [JsonPropertyName("isEnabled")]
    public bool IsEnabled { get; set; } = true;

    [JsonPropertyName("isFromWebStore")]
    public bool IsFromWebStore { get; set; }

    [JsonPropertyName("isDeveloperMode")]
    public bool IsDeveloperMode { get; set; }

    [JsonPropertyName("isBlacklisted")]
    public bool IsBlacklisted { get; set; }

    [JsonPropertyName("hasDangerousPermissions")]
    public bool HasDangerousPermissions { get; set; }

    [JsonPropertyName("installedUtc")]
    public DateTime? InstalledUtc { get; set; }
}