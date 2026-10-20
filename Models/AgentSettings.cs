namespace EndpointSecurityAgent.Models;

public class AgentSettings
{
    public string ServerBaseUrl { get; set; } = string.Empty;
    public int ReportIntervalSeconds { get; set; } = 300;
    public int HighRiskImmediateReportThreshold { get; set; } = 50;
    public string ApiKeyOrDeviceToken { get; set; } = string.Empty;

    public bool UsbPolicyBlocked { get; set; }
    public List<string> ApprovedSoftware { get; set; } = new();
    public List<string> TrustedWifiSsids { get; set; } = new();
    public List<string> MonitoredFolders { get; set; } = new();

    public List<string> BlacklistedExtensionNames { get; set; } = new();
    public List<string> RequiredSecurityExtensions { get; set; } = new();

    public RiskWeights RiskWeights { get; set; } = new();
}

public class RiskWeights
{
    public int FirewallDisabled { get; set; } = 20;
    public int DefenderDisabled { get; set; } = 30;
    public int RealtimeProtectionDisabled { get; set; } = 15;
    public int DefinitionsOutdated { get; set; } = 10;
    public int BitLockerOff { get; set; } = 15;
    public int UnapprovedUsbConnected { get; set; } = 15;
    public int UnauthorizedSoftware { get; set; } = 25;
    public int SuspiciousDownload { get; set; } = 25;
    public int UntrustedWifi { get; set; } = 10;
    public int WindowsUpdatesPending { get; set; } = 10;
    public int UnsupportedWindowsVersion { get; set; } = 20;
    public int BlacklistedExtension { get; set; } = 25;
    public int UnknownPublisherExtension { get; set; } = 10;
    public int DeveloperModeExtension { get; set; } = 30;
    public int SecurityExtensionRemoved { get; set; } = 20;
    public int DangerousExtensionPermissions { get; set; } = 10;
}
