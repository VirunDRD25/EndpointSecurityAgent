using EndpointSecurityAgent;
using EndpointSecurityAgent.Models;
using EndpointSecurityAgent.Services;

var builder = Host.CreateApplicationBuilder(args);

// Allows the compiled .exe to be installed with `sc.exe create` / run as a
// native Windows Service (LocalSystem account recommended — required for
// the BitLocker WMI check to succeed).
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "EndpointSecurityAgent";
});

builder.Services.Configure<AgentSettings>(builder.Configuration.GetSection("AgentSettings"));

// Named HttpClient with sane defaults; ApiClient sets BaseAddress from config.
builder.Services.AddHttpClient<ApiClient>();

builder.Services.AddSingleton<DeviceInfoCollector>();
builder.Services.AddSingleton<FirewallChecker>();
builder.Services.AddSingleton<DefenderChecker>();
builder.Services.AddSingleton<BitLockerChecker>();
builder.Services.AddSingleton<WindowsUpdateChecker>();
builder.Services.AddSingleton<SoftwareInventoryMonitor>();
builder.Services.AddSingleton<FileDownloadMonitor>();
builder.Services.AddSingleton<UsbMonitor>();
builder.Services.AddSingleton<WifiChecker>();
builder.Services.AddSingleton<BrowserExtensionMonitor>();
builder.Services.AddSingleton<RiskScoreCalculator>();

// File Risk Analyzer (metadata-only file detection: name, extension, size,
// SHA-256, location — never file contents). Settings are bound once at
// startup from the "FileRiskAnalyzer" appsettings.json section.
var fileRiskSettings = builder.Configuration
    .GetSection("FileRiskAnalyzer")
    .Get<FileRiskSettings>() ?? new FileRiskSettings();
builder.Services.AddSingleton(fileRiskSettings);
builder.Services.AddSingleton<FileRiskAnalyzer>();

builder.Services.AddHostedService<Worker>();

// Windows Event Log integration so `services.msc` / Event Viewer show agent status.
builder.Logging.AddEventLog(settings =>
{
    settings.SourceName = "EndpointSecurityAgent";
});

var host = builder.Build();
host.Run();