using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Watches Downloads / Desktop / Documents (and mapped USB drives, via
/// UsbMonitor calling WatchDrive) for newly created executable-type files.
/// For each new file it computes a SHA-256 hash and inspects the Authenticode
/// digital signature + publisher, then queues it to be reported.
/// </summary>
public class FileDownloadMonitor : IDisposable
{
    private readonly ILogger<FileDownloadMonitor> _logger;
    private readonly AgentSettings _settings;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<DownloadedFileInfo> _pendingEvents = new();

    private static readonly string[] MonitoredExtensions =
    {
        ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".dll"
    };

    public FileDownloadMonitor(ILogger<FileDownloadMonitor> logger, IOptions<AgentSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
    }

    public void StartWatchingConfiguredFolders()
    {
        foreach (var rawPath in _settings.MonitoredFolders)
        {
            var path = Environment.ExpandEnvironmentVariables(rawPath);
            WatchDrive(path);
        }
    }

    /// <summary>
    /// Starts watching an arbitrary path — used both for the configured
    /// Downloads/Desktop/Documents folders and for USB drive roots once
    /// UsbMonitor detects a new removable drive.
    /// </summary>
    public void WatchDrive(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                _logger.LogWarning("Monitored path does not exist, skipping: {Path}", path);
                return;
            }

            var watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };

            watcher.Created += OnFileCreated;
            watcher.Renamed += OnFileRenamed;
            watcher.Error += (s, e) => _logger.LogWarning(e.GetException(), "FileSystemWatcher error on {Path}", path);

            _watchers.Add(watcher);
            _logger.LogInformation("Watching {Path} for new executables", path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not start watching {Path}", path);
        }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e) => TryEnqueue(e.FullPath);
    private void OnFileRenamed(object sender, RenamedEventArgs e) => TryEnqueue(e.FullPath);

    private void TryEnqueue(string fullPath)
    {
        try
        {
            var ext = Path.GetExtension(fullPath).ToLowerInvariant();
            if (!MonitoredExtensions.Contains(ext)) return;

            // Give the OS a brief moment to release the file handle after write completes.
            Task.Delay(500).ContinueWith(_ =>
            {
                var info = AnalyzeFile(fullPath);
                if (info != null) _pendingEvents.Enqueue(info);
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to queue analysis for {Path}", fullPath);
        }
    }

    private DownloadedFileInfo? AnalyzeFile(string fullPath)
    {
        try
        {
            if (!File.Exists(fullPath)) return null;

            var info = new DownloadedFileInfo
            {
                FileName = Path.GetFileName(fullPath),
                FullPath = fullPath,
                FileType = Path.GetExtension(fullPath).TrimStart('.').ToUpperInvariant(),
                SourceFolder = Path.GetDirectoryName(fullPath) ?? string.Empty,
                DetectedUtc = DateTime.UtcNow
            };

            info.Sha256 = ComputeSha256(fullPath);
            (info.IsDigitallySigned, info.Publisher) = CheckSignature(fullPath);

            // Simple heuristic: unsigned executable dropped in a user-writable
            // location is treated as suspicious and worth flagging for review.
            info.IsSuspicious = !info.IsDigitallySigned &&
                                 (info.FileType is "EXE" or "SCR" or "MSI");

            _logger.LogInformation(
                "New file detected: {File} | SHA256={Hash} | Signed={Signed} | Publisher={Publisher} | Suspicious={Suspicious}",
                info.FileName, info.Sha256, info.IsDigitallySigned, info.Publisher, info.IsSuspicious);

            return info;
        }
        catch (IOException)
        {
            // File still locked / being written — skip silently, it's a best-effort scan.
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to analyze file {Path}", fullPath);
            return null;
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private (bool signed, string publisher) CheckSignature(string path)
    {
        try
        {
            using var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
            var subject = cert.Subject;

            // Extract CN= from the subject string as a friendly publisher name.
            var publisher = subject;
            var cnIndex = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cnIndex >= 0)
            {
                var start = cnIndex + 3;
                var end = subject.IndexOf(',', start);
                publisher = end > start ? subject[start..end] : subject[start..];
            }

            return (true, publisher.Trim('"'));
        }
        catch
        {
            // No embedded Authenticode signature found — this is common (and not
            // by itself proof of malice) but worth flagging per company policy.
            return (false, "Unknown / Unsigned");
        }
    }

    /// <summary>Drains and returns any file events collected since the last call.</summary>
    public List<DownloadedFileInfo> DrainPendingEvents()
    {
        var list = new List<DownloadedFileInfo>();
        while (_pendingEvents.TryDequeue(out var item)) list.Add(item);
        return list;
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
    }
}
