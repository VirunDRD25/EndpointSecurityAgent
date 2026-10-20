using System.Text.Json;
using System.Text.Json.Serialization;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace EndpointSecurityAgent.Services;

/// <summary>Shape of ApprovedSoftware.json.</summary>
internal class ApprovedSoftwareFile
{
    [JsonPropertyName("AllowedSoftware")]
    public List<string> AllowedSoftware { get; set; } = new();
}

/// <summary>
/// Enumerates installed applications from the standard Windows "Uninstall"
/// registry keys (both 64-bit and 32-bit views, plus per-user installs) and
/// flags anything not on the company's approved software list.
/// </summary>
public class SoftwareInventoryMonitor
{
    private readonly ILogger<SoftwareInventoryMonitor> _logger;
    private readonly AgentSettings _settings;

    private static readonly string[] UninstallKeyPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    public SoftwareInventoryMonitor(ILogger<SoftwareInventoryMonitor> logger, IOptions<AgentSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
    }

    public List<string> GetInstalledSoftware()
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var path in UninstallKeyPaths)
            {
                CollectFrom(Registry.LocalMachine, path, results);
            }

            // Per-user installs (e.g. some Chrome/VS Code installs are per-user, not machine-wide)
            CollectFrom(Registry.CurrentUser, UninstallKeyPaths[0], results);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enumerate installed software from registry");
        }

        return results.OrderBy(s => s).ToList();
    }

    private static readonly string ApprovedSoftwareFilePath =
        Path.Combine(AppContext.BaseDirectory, "ApprovedSoftware.json");

    public List<string> FindUnauthorized(List<string> installedSoftware)
    {
        var approved = LoadApprovedSoftwareList();

        if (approved.Count == 0)
        {
            // No allowlist configured anywhere — don't flag everything as unauthorized.
            _logger.LogWarning("No approved software list found (ApprovedSoftware.json missing/empty and appsettings.json ApprovedSoftware is empty) — skipping unauthorized software check.");
            return new List<string>();
        }

        return installedSoftware
            .Where(installed => !approved.Any(approvedName =>
                installed.Contains(approvedName, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    /// <summary>
    /// Reads ApprovedSoftware.json fresh on every call (cheap, small file) so
    /// IT can edit the allowlist and have it take effect on the next report
    /// cycle without restarting the service. Falls back to appsettings.json's
    /// AgentSettings.ApprovedSoftware if the external file doesn't exist.
    /// </summary>
    private List<string> LoadApprovedSoftwareList()
    {
        try
        {
            if (File.Exists(ApprovedSoftwareFilePath))
            {
                var json = File.ReadAllText(ApprovedSoftwareFilePath);
                var parsed = JsonSerializer.Deserialize<ApprovedSoftwareFile>(json);
                if (parsed?.AllowedSoftware is { Count: > 0 })
                    return parsed.AllowedSoftware;

                _logger.LogWarning("ApprovedSoftware.json found but AllowedSoftware list is empty — falling back to appsettings.json");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read/parse ApprovedSoftware.json — falling back to appsettings.json");
        }

        return _settings.ApprovedSoftware;
    }

    private void CollectFrom(RegistryKey root, string subKeyPath, HashSet<string> results)
    {
        using var key = root.OpenSubKey(subKeyPath);
        if (key is null) return;

        foreach (var subKeyName in key.GetSubKeyNames())
        {
            using var subKey = key.OpenSubKey(subKeyName);
            var displayName = subKey?.GetValue("DisplayName") as string;
            var systemComponent = subKey?.GetValue("SystemComponent");
            var releaseType = subKey?.GetValue("ReleaseType") as string;

            // Skip OS components / updates that clutter the uninstall list
            if (string.IsNullOrWhiteSpace(displayName)) continue;
            if (systemComponent is int sc && sc == 1) continue;
            if (releaseType is "Update" or "Hotfix" or "ServicePack") continue;

            results.Add(displayName.Trim());
        }
    }
}
