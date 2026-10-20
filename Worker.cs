using EndpointSecurityAgent.Models;
using EndpointSecurityAgent.Services;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent;

/// <summary>
/// Main loop of the agent. Runs as a Windows Service (via
/// Microsoft.Extensions.Hosting.WindowsServices). On every tick it:
///   1. Collects device/security state from all checkers
///   2. Calculates the risk score
///   3. Reports to the server (and reports immediately, out of cycle,
///      if risk crosses the configured high-risk threshold)
/// </summary>
public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly AgentSettings _settings;

    private readonly DeviceInfoCollector _deviceInfo;
    private readonly FirewallChecker _firewall;
    private readonly DefenderChecker _defender;
    private readonly BitLockerChecker _bitLocker;
    private readonly WindowsUpdateChecker _windowsUpdate;
    private readonly SoftwareInventoryMonitor _software;
    private readonly FileDownloadMonitor _fileMonitor;
    private readonly UsbMonitor _usbMonitor;
    private readonly WifiChecker _wifi;
    private readonly RiskScoreCalculator _riskCalculator;
    private readonly ApiClient _apiClient;
    private readonly BrowserExtensionMonitor _browserExtensionMonitor;
    private readonly FileRiskAnalyzer _fileRiskAnalyzer;

    public Worker(
        ILogger<Worker> logger,
        IOptions<AgentSettings> settings,
        DeviceInfoCollector deviceInfo,
        FirewallChecker firewall,
        DefenderChecker defender,
        BitLockerChecker bitLocker,
        WindowsUpdateChecker windowsUpdate,
        SoftwareInventoryMonitor software,
        FileDownloadMonitor fileMonitor,
        UsbMonitor usbMonitor,
        WifiChecker wifi,
        RiskScoreCalculator riskCalculator,
        ApiClient apiClient,
        BrowserExtensionMonitor browserExtensionMonitor,
        FileRiskAnalyzer fileRiskAnalyzer)
    {
        _logger = logger;
        _settings = settings.Value;
        _deviceInfo = deviceInfo;
        _firewall = firewall;
        _defender = defender;
        _bitLocker = bitLocker;
        _windowsUpdate = windowsUpdate;
        _software = software;
        _fileMonitor = fileMonitor;
        _usbMonitor = usbMonitor;
        _wifi = wifi;
        _riskCalculator = riskCalculator;
        _apiClient = apiClient;
        _browserExtensionMonitor = browserExtensionMonitor;
        _fileRiskAnalyzer = fileRiskAnalyzer;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Endpoint Security Agent starting up");

        // Event-driven watchers start once and run continuously between report cycles.
        _fileMonitor.StartWatchingConfiguredFolders();
        _usbMonitor.Start();

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Keep track of installed software between cycles so we can detect
        // NEW installs, not just re-flag the same approved baseline every time.
        List<string> previousSoftwareSnapshot = _software.GetInstalledSoftware();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var report = await BuildReportAsync(previousSoftwareSnapshot, stoppingToken);
                previousSoftwareSnapshot = report.InstalledSoftware;

                bool sent = await _apiClient.SendReportAsync(report, stoppingToken);

                if (!sent)
                {
                    _logger.LogWarning("Report could not be delivered; it will be superseded by the next cycle's report.");
                    // Production hardening idea: persist unsent reports to a local
                    // queue file and retry/flush them once connectivity returns.
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error in agent report cycle");
            }

            await Task.Delay(TimeSpan.FromSeconds(_settings.ReportIntervalSeconds), stoppingToken);
        }
    }

    private Task<DeviceReport> BuildReportAsync(List<string> previousSoftwareSnapshot, CancellationToken ct)
    {
        var report = new DeviceReport();

        _deviceInfo.Populate(report);
        report.Firewall = _firewall.Check();
        report.Defender = _defender.Check();
        report.BitLocker = _bitLocker.Check();
        report.WindowsUpdate = _windowsUpdate.Check();
        report.Wifi = _wifi.Check();

        report.InstalledSoftware = _software.GetInstalledSoftware();
        report.UnauthorizedSoftware = _software.FindUnauthorized(report.InstalledSoftware);

        report.RecentDownloads = _fileMonitor.DrainPendingEvents();
        report.UsbEvents = _usbMonitor.DrainPendingEvents();
        report.BrowserExtensions = _browserExtensionMonitor.Scan();
        report.MissingRequiredSecurityExtensions =
            _browserExtensionMonitor.GetMissingRequiredSecurityExtensions(report.BrowserExtensions);

        // File Risk Analyzer: metadata-only scan of Downloads/Desktop/Documents/
        // Startup (never file contents) — see FileRiskAnalyzer.ScanWatchedFolders().
        report.FileRisks = _fileRiskAnalyzer.ScanWatchedFolders();

        _riskCalculator.Calculate(report);

        if (report.RiskScore >= _settings.HighRiskImmediateReportThreshold)
        {
            _logger.LogWarning("HIGH RISK detected on this device — score {Score}. Factors: {Factors}",
                report.RiskScore, string.Join("; ", report.RiskFactors));
        }

        return Task.FromResult(report);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Endpoint Security Agent shutting down");
        _fileMonitor.Dispose();
        _usbMonitor.Dispose();
        await base.StopAsync(cancellationToken);
    }
}