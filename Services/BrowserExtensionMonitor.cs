using System.Text.Json;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Detects installed browser extensions across Chrome, Edge, Brave, Opera,
/// and Firefox. Chromium-based browsers (Chrome, Edge, Brave, Opera) are
/// read from each profile's "Preferences" (or "Secure Preferences") JSON
/// file — the same source of truth Chrome itself uses. This avoids having
/// to separately walk the Extensions folder and resolve localized manifest
/// names, and gives us enable/disable state, install time, and
/// developer-mode detection in one read.
///
/// Firefox uses a completely different profile layout and extension
/// metadata format (extensions.json, not a Chromium "Preferences" file),
/// so it is handled by a dedicated parsing path instead.
/// </summary>
public class BrowserExtensionMonitor
{
    private readonly ILogger<BrowserExtensionMonitor> _logger;
    private readonly AgentSettings _settings;

    // Chromium's Extension::Location enum values that matter to us.
    private const int LocationInternal = 1;          // Chrome Web Store
    private const int LocationUnpacked = 4;           // "Load unpacked" (Developer Mode)
    private const int LocationComponent = 5;          // built-in, e.g. PDF viewer — skip
    private const int LocationCommandLine = 8;        // --load-extension flag (developer/unpacked)
    private const int LocationExternalComponent = 10; // built-in, skip

    private static readonly HashSet<string> DangerousPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "tabs", "cookies", "webRequest", "webRequestBlocking", "history",
        "downloads", "clipboardRead", "clipboardWrite", "nativeMessaging",
        "management", "proxy", "debugger", "<all_urls>"
    };

    // Relative paths under each user's LOCALAPPDATA or APPDATA
    private static readonly (string Browser, string RelativePath, bool UseRoaming)[] BrowserRelativePaths =
    {
        ("Chrome", @"Google\Chrome\User Data",               false), // LOCALAPPDATA
        ("Edge",   @"Microsoft\Edge\User Data",              false), // LOCALAPPDATA
        ("Brave",  @"BraveSoftware\Brave-Browser\User Data", false), // LOCALAPPDATA
        ("Opera",  @"Opera Software\Opera Stable",           true),  // APPDATA (roaming)
    };

    // Firefox uses a completely different profile layout and extension
    // metadata format (extensions.json, not a Chromium "Preferences" file),
    // so it's handled by a dedicated code path below instead of the
    // Chromium BrowserRelativePaths/ParsePreferences pipeline.
    private const string FirefoxRelativePath = @"Mozilla\Firefox\Profiles"; // APPDATA (roaming)

    public BrowserExtensionMonitor(ILogger<BrowserExtensionMonitor> logger, IOptions<AgentSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
    }

    public List<BrowserExtensionInfo> Scan()
    {
        var results = new List<BrowserExtensionInfo>();

        foreach (var userProfilePath in GetRealUserProfilePaths())
        {
            var localAppData = Path.Combine(userProfilePath, "AppData", "Local");
            var roamingAppData = Path.Combine(userProfilePath, "AppData", "Roaming");

            foreach (var (browser, relativePath, useRoaming) in BrowserRelativePaths)
            {
                var userDataRoot = Path.Combine(useRoaming ? roamingAppData : localAppData, relativePath);

                try
{
    if (!Directory.Exists(userDataRoot))
    {
        _logger.LogInformation("{Browser}: profile folder not found at {Path} (likely not installed)", browser, userDataRoot);
        continue;
    }

    foreach (var profileDir in GetProfileDirectories(userDataRoot))
    {
        var profileName = Path.GetFileName(profileDir);
        var securePrefsPath = Path.Combine(profileDir, "Secure Preferences");
        var plainPrefsPath = Path.Combine(profileDir, "Preferences");

        if (!File.Exists(securePrefsPath) && !File.Exists(plainPrefsPath))
        {
            _logger.LogInformation("{Browser}: no Preferences file at {Path}", browser, profileDir);
            continue;
        }

        // Most Chromium browsers (Chrome/Edge/Brave) keep extension install
        // state in "Secure Preferences" (tamper-protected with a MAC).
        // Opera instead keeps it in the plain "Preferences" file and uses
        // "Secure Preferences" only for blocklist/sync/UI settings. Read
        // both when present and merge by extension ID, preferring the
        // Secure Preferences entry if the same extension appears in both,
        // so this works correctly regardless of which file a given
        // Chromium browser actually uses.
        var merged = new Dictionary<string, BrowserExtensionInfo>(StringComparer.OrdinalIgnoreCase);

        if (File.Exists(securePrefsPath))
            foreach (var ext in ParsePreferences(browser, profileName, securePrefsPath))
                merged[ext.ExtensionId] = ext;

        if (File.Exists(plainPrefsPath))
            foreach (var ext in ParsePreferences(browser, profileName, plainPrefsPath))
                merged.TryAdd(ext.ExtensionId, ext);
        if (merged.Count == 0)
        {
            var extFolderResults = ParseExtensionsFolder(browser, profileName, profileDir);
            if (extFolderResults.Count > 0)
            {
                _logger.LogInformation("{Browser}: profile '{Profile}' — Preferences had no extension data; found {Count} extension(s) by scanning Extensions folder directly",
                 browser, profileName, extFolderResults.Count);
                    foreach (var ext in extFolderResults) merged[ext.ExtensionId] = ext;
            }
        }
        _logger.LogInformation("{Browser}: profile '{Profile}' — found {Count} extension(s) total", browser, profileName, merged.Count);
        results.AddRange(merged.Values);
    }
}
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed scanning {Browser} extensions in {Path}", browser, userDataRoot);
                }
            }

            // Firefox: separate pipeline (different file format/profile layout).
            try
            {
                var firefoxProfilesRoot = Path.Combine(roamingAppData, FirefoxRelativePath);
                if (Directory.Exists(firefoxProfilesRoot))
                {
                    foreach (var profileDir in Directory.GetDirectories(firefoxProfilesRoot))
                    {
                        var extensionsJsonPath = Path.Combine(profileDir, "extensions.json");
                        if (!File.Exists(extensionsJsonPath)) continue;

                        var profileName = Path.GetFileName(profileDir);
                        var found = ParseFirefoxExtensions(profileName, extensionsJsonPath);
                        _logger.LogInformation("Firefox: profile '{Profile}' — found {Count} extension(s)", profileName, found.Count);
                        results.AddRange(found);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed scanning Firefox extensions for profile {Path}", userProfilePath);
            }
        }

        // Flag blacklist / dangerous-permission matches now that we have the full set.
        foreach (var ext in results)
        {
            ext.IsBlacklisted = _settings.BlacklistedExtensionNames.Any(b =>
                ext.Name.Contains(b, StringComparison.OrdinalIgnoreCase));

            ext.HasDangerousPermissions = ext.Permissions.Any(p => DangerousPermissions.Contains(p));
        }

        return results;
    }

    /// <summary>
    /// Finds all real user profile directories on this machine by reading
    /// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList — the
    /// same registry key Windows itself uses to enumerate user profiles.
    /// This works correctly when the agent runs as LocalSystem because it
    /// does not rely on %LOCALAPPDATA% or %APPDATA% (which resolve to the
    /// system account's own profile, not the logged-in user's profile).
    /// </summary>
    private IEnumerable<string> GetRealUserProfilePaths()
    {
        var profiles = new List<string>();

        try
        {
            using var profileList = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");

            if (profileList == null) return profiles;

            foreach (var sidKey in profileList.GetSubKeyNames())
            {
                // Skip system accounts — we only want real human user profiles.
                // System SIDs: S-1-5-18 (LocalSystem), S-1-5-19 (LocalService),
                // S-1-5-20 (NetworkService). Real user SIDs are longer.
                if (sidKey == "S-1-5-18" || sidKey == "S-1-5-19" || sidKey == "S-1-5-20")
                    continue;

                using var key = profileList.OpenSubKey(sidKey);
                var profilePath = key?.GetValue("ProfileImagePath") as string;

                if (string.IsNullOrWhiteSpace(profilePath)) continue;

                // Expand any environment variables in the path (e.g. %SystemDrive%)
                profilePath = Environment.ExpandEnvironmentVariables(profilePath);

                if (!Directory.Exists(profilePath)) continue;

                // Skip well-known system profile paths
                if (profilePath.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase)) continue;

                profiles.Add(profilePath);
                _logger.LogDebug("Found user profile to scan: {Path}", profilePath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enumerate user profiles from registry");
        }

        return profiles;
    }

    /// <summary>Company-required extensions that are not present and enabled anywhere.</summary>
    public List<string> GetMissingRequiredSecurityExtensions(List<BrowserExtensionInfo> found)
    {
        if (_settings.RequiredSecurityExtensions.Count == 0) return new List<string>();

        var presentEnabledNames = found.Where(e => e.IsEnabled).Select(e => e.Name).ToList();

        return _settings.RequiredSecurityExtensions
            .Where(required => !presentEnabledNames.Any(name =>
                name.Contains(required, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    private IEnumerable<string> GetProfileDirectories(string userDataRoot)
{
    // Opera previously stored everything flat directly in "Opera Stable\".
    // Current Opera versions support multiple profiles and use the same
    // "Default" / "Profile N" subfolder layout as other Chromium browsers —
    // check both, falling back to the flat layout only if neither exists.
    if (userDataRoot.Contains("Opera Software", StringComparison.OrdinalIgnoreCase))
    {
        bool foundSubProfile = false;

        if (Directory.Exists(Path.Combine(userDataRoot, "Default")))
        {
            yield return Path.Combine(userDataRoot, "Default");
            foundSubProfile = true;
        }

        string[] operaProfileDirs;
        try { operaProfileDirs = Directory.GetDirectories(userDataRoot, "Profile *"); }
        catch { operaProfileDirs = Array.Empty<string>(); }

        foreach (var dir in operaProfileDirs)
        {
            yield return dir;
            foundSubProfile = true;
        }

        if (!foundSubProfile)
            yield return userDataRoot; // older flat-layout Opera

        yield break;
    }

    if (Directory.Exists(Path.Combine(userDataRoot, "Default")))
        yield return Path.Combine(userDataRoot, "Default");

    string[] profileDirs;
    try { profileDirs = Directory.GetDirectories(userDataRoot, "Profile *"); }
    catch { yield break; }

    foreach (var dir in profileDirs)
        yield return dir;
}

   private List<BrowserExtensionInfo> ParsePreferences(string browser, string profileName, string prefsPath)
{
    var list = new List<BrowserExtensionInfo>();

    _logger.LogInformation("{Browser}/{Profile}: reading preferences from {Path}", browser, profileName, prefsPath);

    try
    {
        using var stream = File.Open(prefsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var doc = JsonDocument.Parse(stream);

        if (!doc.RootElement.TryGetProperty("extensions", out var extensionsEl))
        {
            _logger.LogInformation("{Browser}/{Profile}: Preferences file has no top-level 'extensions' key", browser, profileName);
            return list;
        }
        if (!extensionsEl.TryGetProperty("settings", out var settingsEl))
        {
            var subKeys = string.Join(", ", extensionsEl.EnumerateObject().Select(p => p.Name));
            _logger.LogInformation("{Browser}/{Profile}: 'extensions' key has no 'settings' sub-key. Available sub-keys: [{Keys}]", browser, profileName, subKeys);
            return list;
        }

        var rawEntries = settingsEl.EnumerateObject().ToList();
        _logger.LogInformation("{Browser}/{Profile}: extensions.settings has {Count} raw entries", browser, profileName, rawEntries.Count);

        foreach (var entry in rawEntries)
        {
            try
            {
                var info = ParseExtensionEntry(browser, profileName, entry.Name, entry.Value);
                if (info != null)
                {
                    list.Add(info);
                }
                else
                {
                    int loc = entry.Value.TryGetProperty("location", out var locEl) && locEl.TryGetInt32(out var l) ? l : -1;
                    bool hasManifest = entry.Value.TryGetProperty("manifest", out _);
                    _logger.LogInformation("{Browser}/{Profile}: entry {Id} filtered out (location={Location}, hasManifest={HasManifest})",
                        browser, profileName, entry.Name, loc, hasManifest);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed parsing extension entry {Id}", entry.Name);
            }
        }
    }
    catch (IOException ex)
    {
        // Preferences file locked by a running browser — skip this cycle, try again next time.
        _logger.LogInformation("{Browser}/{Profile}: Preferences file locked (browser likely still running) — {Message}", browser, profileName, ex.Message);
    }
    catch (Exception ex)
    {
        _logger.LogWarning(ex, "Failed reading preferences file {Path}", prefsPath);
    }

    return list;
}

/// <summary>
/// Fallback for browsers (observed with Opera) whose Preferences/Secure
/// Preferences files don't store extension install state under
/// extensions.settings the way Chrome/Edge/Brave do. Reads installed
/// extensions directly from the on-disk Extensions folder instead —
/// every Chromium browser keeps a copy of each extension's manifest.json
/// there regardless of what it does in Preferences. Enabled/disabled
/// state can't be determined this way (that's Preferences-only data),
/// so results from this path are always reported as enabled.
/// </summary>
private List<BrowserExtensionInfo> ParseExtensionsFolder(string browser, string profileName, string profileDir)
{
    var list = new List<BrowserExtensionInfo>();
    var extensionsRoot = Path.Combine(profileDir, "Extensions");

    if (!Directory.Exists(extensionsRoot)) return list;

    string[] extensionDirs;
    try { extensionDirs = Directory.GetDirectories(extensionsRoot); }
    catch (Exception ex)
    {
        _logger.LogWarning(ex, "Failed listing Extensions folder {Path}", extensionsRoot);
        return list;
    }

    foreach (var extDir in extensionDirs)
    {
        var extensionId = Path.GetFileName(extDir);

        // Extension IDs are always 32 lowercase a-p letters — skip anything
        // else (e.g. "Temp" staging folders Chromium sometimes leaves behind).
        if (extensionId.Length != 32 || !extensionId.All(c => c >= 'a' && c <= 'p')) continue;

        string[] versionDirs;
        try { versionDirs = Directory.GetDirectories(extDir); }
        catch { continue; }
        if (versionDirs.Length == 0) continue;

        var versionDir = versionDirs
            .OrderByDescending(d => Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)
            .First();

        var manifestPath = Path.Combine(versionDir, "manifest.json");
        if (!File.Exists(manifestPath)) continue;

        try
        {
            var info = ParseManifestFile(browser, profileName, extensionId, manifestPath, extDir);
            if (info != null) list.Add(info);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed parsing manifest for {Id} at {Path}", extensionId, manifestPath);
        }
    }

    return list;
}

private BrowserExtensionInfo? ParseManifestFile(string browser, string profile, string extensionId, string manifestPath, string extDirForTimestamp)
{
    using var stream = File.Open(manifestPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    using var doc = JsonDocument.Parse(stream);
    var root = doc.RootElement;

    string name = root.TryGetProperty("name", out var nameEl) ? nameEl.GetString() ?? extensionId : extensionId;
    if (name.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase)) name = extensionId;

    string version = root.TryGetProperty("version", out var verEl) ? verEl.GetString() ?? "Unknown" : "Unknown";

    var permissions = new List<string>();
    if (root.TryGetProperty("permissions", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array)
        foreach (var p in permsEl.EnumerateArray())
            if (p.ValueKind == JsonValueKind.String) permissions.Add(p.GetString()!);

    if (root.TryGetProperty("host_permissions", out var hostPermsEl) && hostPermsEl.ValueKind == JsonValueKind.Array)
        foreach (var p in hostPermsEl.EnumerateArray())
            if (p.ValueKind == JsonValueKind.String) permissions.Add(p.GetString()!);

    // Presence of an "update_url" pointing at a known store is the closest
    // signal we have for web-store provenance without Preferences data.
    bool fromWebStore = root.TryGetProperty("update_url", out var updateUrlEl)
        && updateUrlEl.ValueKind == JsonValueKind.String
        && (updateUrlEl.GetString()?.Contains("google.com", StringComparison.OrdinalIgnoreCase) == true
            || updateUrlEl.GetString()?.Contains("opera.com", StringComparison.OrdinalIgnoreCase) == true);

    DateTime? installedUtc = null;
    try { installedUtc = Directory.GetCreationTimeUtc(extDirForTimestamp); } catch { }

    return new BrowserExtensionInfo
    {
        Browser = browser,
        Profile = profile,
        ExtensionId = extensionId,
        Name = name,
        Version = version,
        Publisher = "Unknown",
        Permissions = permissions.Distinct().ToList(),
        IsEnabled = true, // can't be determined from disk alone
        IsFromWebStore = fromWebStore,
        IsDeveloperMode = false, // unpacked/dev extensions don't live in this folder
        InstalledUtc = installedUtc
    };
}
    private BrowserExtensionInfo? ParseExtensionEntry(string browser, string profile, string extensionId, JsonElement entry)
    {
        int location = entry.TryGetProperty("location", out var locEl) && locEl.TryGetInt32(out var l) ? l : 0;

        // Skip Chrome's own built-in components (PDF viewer, etc.) — not user-installed, pure noise.
        if (location == LocationComponent || location == LocationExternalComponent) return null;

        if (!entry.TryGetProperty("manifest", out var manifestEl))
            return null; // entry with no embedded manifest — usually a leftover from an uninstall

        string name = manifestEl.TryGetProperty("name", out var nameEl)
            ? nameEl.GetString() ?? extensionId
            : extensionId;

        // Unresolved localized name — use the extension ID instead
        if (name.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase)) name = extensionId;

        string version = manifestEl.TryGetProperty("version", out var verEl)
            ? verEl.GetString() ?? "Unknown"
            : "Unknown";

        string publisher = "Unknown";
        if (manifestEl.TryGetProperty("author", out var authorEl))
        {
            publisher = authorEl.ValueKind == JsonValueKind.String
                ? authorEl.GetString() ?? "Unknown"
                : (authorEl.TryGetProperty("email", out var emailEl)
                    ? emailEl.GetString() ?? "Unknown"
                    : "Unknown");
        }

        var permissions = new List<string>();
        if (manifestEl.TryGetProperty("permissions", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array)
            foreach (var p in permsEl.EnumerateArray())
                if (p.ValueKind == JsonValueKind.String) permissions.Add(p.GetString()!);

        if (manifestEl.TryGetProperty("host_permissions", out var hostPermsEl) && hostPermsEl.ValueKind == JsonValueKind.Array)
            foreach (var p in hostPermsEl.EnumerateArray())
                if (p.ValueKind == JsonValueKind.String) permissions.Add(p.GetString()!);

        bool isEnabled = !(entry.TryGetProperty("state", out var stateEl)
            && stateEl.TryGetInt32(out var state)
            && state == 0);

        bool fromWebStore = location == LocationInternal ||
            (entry.TryGetProperty("from_webstore", out var fwsEl) && fwsEl.ValueKind == JsonValueKind.True);

        bool isDeveloperMode = location == LocationUnpacked || location == LocationCommandLine;

        DateTime? installedUtc = null;
        if (entry.TryGetProperty("install_time", out var installEl)
            && installEl.ValueKind == JsonValueKind.String
            && long.TryParse(installEl.GetString(), out var webkitMicroseconds)
            && webkitMicroseconds > 0)
        {
            try
            {
                // Chrome/WebKit timestamp: microseconds since 1601-01-01 UTC.
                installedUtc = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .AddTicks(webkitMicroseconds * 10);
            }
            catch { /* out of DateTime range — ignore */ }
        }

        return new BrowserExtensionInfo
        {
            Browser = browser,
            Profile = profile,
            ExtensionId = extensionId,
            Name = name,
            Version = version,
            Publisher = publisher,
            Permissions = permissions.Distinct().ToList(),
            IsEnabled = isEnabled,
            IsFromWebStore = fromWebStore,
            IsDeveloperMode = isDeveloperMode,
            InstalledUtc = installedUtc
        };
    }

    /// <summary>
    /// Firefox stores extension metadata in extensions.json (JSON, not
    /// SQLite) at Mozilla\Firefox\Profiles\&lt;profile&gt;\extensions.json —
    /// a completely different schema from Chromium's Preferences file.
    /// </summary>
    private List<BrowserExtensionInfo> ParseFirefoxExtensions(string profileName, string extensionsJsonPath)
    {
        var list = new List<BrowserExtensionInfo>();

        try
        {
            using var stream = File.Open(extensionsJsonPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var doc = JsonDocument.Parse(stream);

            if (!doc.RootElement.TryGetProperty("addons", out var addonsEl) || addonsEl.ValueKind != JsonValueKind.Array)
                return list;

            foreach (var addon in addonsEl.EnumerateArray())
            {
                try
                {
                    var info = ParseFirefoxAddonEntry(profileName, addon);
                    if (info != null) list.Add(info);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed parsing Firefox addon entry in {Path}", extensionsJsonPath);
                }
            }
        }
        catch (IOException)
        {
            // extensions.json locked by a running Firefox instance — skip this cycle, try again next time.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed reading Firefox extensions.json {Path}", extensionsJsonPath);
        }

        return list;
    }

    private BrowserExtensionInfo? ParseFirefoxAddonEntry(string profile, JsonElement addon)
    {
        // Only real user-installed extensions live under "app-profile".
        // Built-in/system add-ons (Form Autofill, Screenshots, Pocket, etc.)
        // come from "app-system-defaults" / "app-builtin" / "app-global" —
        // skip them the same way Chromium's LocationComponent is skipped.
        string location = addon.TryGetProperty("location", out var locEl) ? locEl.GetString() ?? "" : "";
        if (!string.Equals(location, "app-profile", StringComparison.OrdinalIgnoreCase))
            return null;

        // "type" can be "extension", "theme", "locale", "dictionary" — we only care about extensions.
        string type = addon.TryGetProperty("type", out var typeEl) ? typeEl.GetString() ?? "" : "";
        if (!string.IsNullOrEmpty(type) && !string.Equals(type, "extension", StringComparison.OrdinalIgnoreCase))
            return null;

        string extensionId = addon.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "Unknown" : "Unknown";

        string name = extensionId;
        string publisher = "Unknown";
        if (addon.TryGetProperty("defaultLocale", out var localeEl))
        {
            if (localeEl.TryGetProperty("name", out var nameEl))
                name = nameEl.GetString() ?? extensionId;
            if (localeEl.TryGetProperty("creator", out var creatorEl) && creatorEl.ValueKind == JsonValueKind.String)
                publisher = creatorEl.GetString() ?? "Unknown";
        }

        string version = addon.TryGetProperty("version", out var verEl) ? verEl.GetString() ?? "Unknown" : "Unknown";

        var permissions = new List<string>();
        if (addon.TryGetProperty("userPermissions", out var userPermsEl))
        {
            if (userPermsEl.TryGetProperty("permissions", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array)
                foreach (var p in permsEl.EnumerateArray())
                    if (p.ValueKind == JsonValueKind.String) permissions.Add(p.GetString()!);

            if (userPermsEl.TryGetProperty("origins", out var originsEl) && originsEl.ValueKind == JsonValueKind.Array)
                foreach (var o in originsEl.EnumerateArray())
                    if (o.ValueKind == JsonValueKind.String) permissions.Add(o.GetString()!);
        }

        bool active = addon.TryGetProperty("active", out var activeEl) && activeEl.ValueKind == JsonValueKind.True;
        bool userDisabled = addon.TryGetProperty("userDisabled", out var userDisEl) && userDisEl.ValueKind == JsonValueKind.True;
        bool isEnabled = active && !userDisabled;

        // AMO (addons.mozilla.org) is Firefox's equivalent of the Chrome Web Store.
        bool fromWebStore = false;
        if (addon.TryGetProperty("installTelemetryInfo", out var telemetryEl)
            && telemetryEl.TryGetProperty("source", out var sourceEl)
            && sourceEl.ValueKind == JsonValueKind.String)
        {
            fromWebStore = string.Equals(sourceEl.GetString(), "amo", StringComparison.OrdinalIgnoreCase);
        }

        // signedState: 0/negative = unsigned (unpacked/developer-loaded), positive = signed by AMO.
        // foreignInstall means it was dropped in by a third-party installer, not the store — also dev-adjacent risk.
        bool isDeveloperMode = false;
        if (addon.TryGetProperty("signedState", out var signedEl) && signedEl.TryGetInt32(out var signedState))
            isDeveloperMode = signedState <= 0;
        if (addon.TryGetProperty("foreignInstall", out var foreignEl) && foreignEl.ValueKind == JsonValueKind.True)
            isDeveloperMode = true;

        DateTime? installedUtc = null;
        if (addon.TryGetProperty("installDate", out var installEl) && installEl.TryGetInt64(out var installEpochMs) && installEpochMs > 0)
        {
            try
            {
                installedUtc = DateTimeOffset.FromUnixTimeMilliseconds(installEpochMs).UtcDateTime;
            }
            catch { /* out of range — ignore */ }
        }

        return new BrowserExtensionInfo
        {
            Browser = "Firefox",
            Profile = profile,
            ExtensionId = extensionId,
            Name = name,
            Version = version,
            Publisher = publisher,
            Permissions = permissions.Distinct().ToList(),
            IsEnabled = isEnabled,
            IsFromWebStore = fromWebStore,
            IsDeveloperMode = isDeveloperMode,
            InstalledUtc = installedUtc
        };
    }
}