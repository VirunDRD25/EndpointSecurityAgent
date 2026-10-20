using System.Management;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Checks Windows Update state: last installed update, count of pending
/// updates (via the Windows Update Agent COM API), and whether the OS build
/// is still within Microsoft's supported lifecycle.
/// </summary>
public class WindowsUpdateChecker
{
    private readonly ILogger<WindowsUpdateChecker> _logger;

    // Minimum supported build numbers — update this list as Microsoft's
    // support lifecycle changes. Builds below these are past end-of-support.
    private const int MinSupportedWin10Build = 19045; // 22H2
    private const int MinSupportedWin11Build = 22621; // 22H2

    public WindowsUpdateChecker(ILogger<WindowsUpdateChecker> logger)
    {
        _logger = logger;
    }

    public WindowsUpdateStatus Check()
    {
        var status = new WindowsUpdateStatus();

        status.LastInstalledUtc = GetLastInstalledUpdateDate();
        status.PendingUpdateCount = GetPendingUpdateCount();
        status.IsSupportedVersion = IsBuildSupported();

        return status;
    }

    private DateTime? GetLastInstalledUpdateDate()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT InstalledOn FROM Win32_QuickFixEngineering");

            DateTime? latest = null;
            foreach (ManagementObject obj in searcher.Get())
            {
                var raw = obj["InstalledOn"]?.ToString();
                if (DateTime.TryParse(raw, out var installed))
                {
                    if (latest is null || installed > latest)
                        latest = installed;
                }
            }
            return latest?.ToUniversalTime();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read last installed update via Win32_QuickFixEngineering");
            return null;
        }
    }

    private int GetPendingUpdateCount()
    {
        try
        {
            // Windows Update Agent COM API — works without admin rights for a search.
            dynamic updateSession = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session")!)!;
            dynamic updateSearcher = updateSession.CreateUpdateSearcher();

            // "IsInstalled=0" -> not yet installed; keep this fast/lightweight.
            dynamic searchResult = updateSearcher.Search("IsInstalled=0 and IsHidden=0");
            int count = searchResult.Updates.Count;
            return count;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not query Windows Update Agent for pending updates (this can be slow/blocked by policy)");
            return 0;
        }
    }

    private bool IsBuildSupported()
    {
        try
        {
            var os = Environment.OSVersion.Version;
            int build = os.Build;

            // crude split: Win11 starts at build 22000
            bool isWin11 = build >= 22000;
            return isWin11 ? build >= MinSupportedWin11Build : build >= MinSupportedWin10Build;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not determine OS build support status");
            return true; // fail open — don't falsely flag on error
        }
    }
}
