using System.Security.Cryptography;
using System.Text.Json;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services
{
    public class FileRiskAnalyzer
    {
        private readonly ILogger<FileRiskAnalyzer> _logger;
        private readonly FileRiskSettings _settings;
        private readonly HashSet<string> _knownMaliciousHashes;
        private Dictionary<string, DateTime> _seenFiles;
        private readonly string _statePath;

        private static readonly Dictionary<string, string> ExtensionCategories = new(StringComparer.OrdinalIgnoreCase)
        {
            [".exe"] = "Executable", [".dll"] = "Executable",
            [".ps1"] = "Script", [".bat"] = "Script", [".cmd"] = "Script", [".vbs"] = "Script", [".js"] = "Script",
            [".docx"] = "Office", [".xlsx"] = "Office", [".pptx"] = "Office", [".doc"] = "Office", [".xls"] = "Office",
            [".zip"] = "Archive", [".rar"] = "Archive", [".7z"] = "Archive",
            [".iso"] = "Disk image", [".img"] = "Disk image",
            [".pdf"] = "Document", [".txt"] = "Document",
            [".scr"] = "Potentially dangerous", [".hta"] = "Potentially dangerous", [".msi"] = "Potentially dangerous"
        };

        private static readonly string[] SuspiciousKeywords =
            { "password", "credential", "secret", "confidential", "keygen", "crack" };

        public FileRiskAnalyzer(ILogger<FileRiskAnalyzer> logger, FileRiskSettings settings)
        {
            _logger = logger;
            _settings = settings;
            _statePath = Path.Combine(AppContext.BaseDirectory, _settings.StateFilePath);
            _knownMaliciousHashes = LoadKnownHashes();
            _seenFiles = LoadState();
        }

        public List<FileRiskInfo> ScanWatchedFolders()
        {
            var results = new List<FileRiskInfo>();
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            foreach (var folderName in _settings.WatchedFolders)
            {
                var folderPath = ResolveFolderPath(folderName, userProfile);
                if (folderPath == null || !Directory.Exists(folderPath)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(folderPath, "*", SearchOption.TopDirectoryOnly);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not enumerate folder {Folder}", folderPath);
                    continue;
                }

                foreach (var filePath in files)
                {
                    try
                    {
                        var info = AnalyzeFile(filePath, folderName);
                        if (info != null) results.Add(info);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to analyze file {File}", filePath);
                    }
                }
            }

            SaveState();
            return results;
        }

        private string? ResolveFolderPath(string folderName, string userProfile) => folderName switch
        {
            "Downloads" => Path.Combine(userProfile, "Downloads"),
            "Desktop" => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "Documents" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "Startup" => Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            _ => Directory.Exists(folderName) ? folderName : null
        };

        private FileRiskInfo? AnalyzeFile(string filePath, string location)
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists) return null;

            var lastRelevant = fi.LastWriteTimeUtc > fi.CreationTimeUtc ? fi.LastWriteTimeUtc : fi.CreationTimeUtc;

            // Only report files that are new or changed since the last scan
            if (_seenFiles.TryGetValue(filePath, out var lastSeen) && lastSeen >= lastRelevant)
                return null;

            _seenFiles[filePath] = lastRelevant;

            var extension = fi.Extension;
            var category = ExtensionCategories.TryGetValue(extension, out var cat) ? cat : "Other";

            var info = new FileRiskInfo
            {
                FileName = fi.Name,
                FilePath = fi.FullName,
                Extension = extension,
                Category = category,
                SizeBytes = fi.Length,
                CreatedUtc = fi.CreationTimeUtc,
                ModifiedUtc = fi.LastWriteTimeUtc,
                Location = location
            };

            if (fi.Length > 0 && fi.Length <= _settings.MaxHashSizeBytes)
                info.Sha256 = ComputeSha256(filePath);

            CalculateRisk(info);
            return info;
        }

        private void CalculateRisk(FileRiskInfo info)
        {
            if (!string.IsNullOrEmpty(info.Sha256) && _knownMaliciousHashes.Contains(info.Sha256))
            {
                info.RiskLevel = "High";
                info.RiskReasons.Add("SHA-256 matches a known malicious hash");
                return;
            }

            var score = 0;
            var reasons = new List<string>();

            if (HasDoubleExtension(info.FileName))
            {
                score += 40;
                reasons.Add("Double extension detected (e.g. invoice.pdf.exe)");
            }

            if (info.Category == "Potentially dangerous")
            {
                score += 30;
                reasons.Add($"Potentially dangerous file type ({info.Extension})");
            }

            if ((info.Category == "Executable" || info.Category == "Script") &&
                (info.Location == "Downloads" || info.Location == "Desktop"))
            {
                score += 25;
                reasons.Add($"{info.Category} found in {info.Location}");
            }

            if (info.Category == "Script" && info.Location == "Startup")
            {
                score += 50;
                reasons.Add("Script located in the Startup folder");
            }

            var ageMinutes = (DateTime.UtcNow - info.CreatedUtc).TotalMinutes;
            if (ageMinutes <= _settings.RecentFileWindowMinutes &&
                (info.Category is "Executable" or "Script" or "Potentially dangerous"))
            {
                score += 15;
                reasons.Add($"Recently created {info.Category.ToLower()} file");
            }

            foreach (var keyword in SuspiciousKeywords)
            {
                if (info.FileName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    score += 10;
                    reasons.Add($"Suspicious keyword in filename: '{keyword}'");
                }
            }

            if (info.Category == "Executable" && info.SizeBytes > 200 * 1024 * 1024)
            {
                score += 10;
                reasons.Add("Unusually large executable file");
            }

            info.RiskReasons = reasons;
            info.RiskLevel = score switch
            {
                >= 50 => "High",
                >= 20 => "Medium",
                _ => "Low"
            };
        }

        private static bool HasDoubleExtension(string fileName)
        {
            var dangerousExts = new[] { "exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "hta", "msi" };
            var parts = fileName.Split('.');
            if (parts.Length < 3) return false;
            return dangerousExts.Contains(parts[^1].ToLowerInvariant());
        }

        private static string ComputeSha256(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return Convert.ToHexString(sha256.ComputeHash(stream)); // uppercase hex
        }

        private HashSet<string> LoadKnownHashes()
        {
            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, _settings.KnownMaliciousHashesPath);
                if (!File.Exists(path)) return new HashSet<string>();
                var hashes = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? new List<string>();
                return new HashSet<string>(hashes.Select(h => h.ToUpperInvariant()));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not load known malicious hashes file");
                return new HashSet<string>();
            }
        }

        private Dictionary<string, DateTime> LoadState()
        {
            try
            {
                if (!File.Exists(_statePath)) return new Dictionary<string, DateTime>();
                return JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(_statePath)) ?? new();
            }
            catch { return new Dictionary<string, DateTime>(); }
        }

        private void SaveState()
        {
            try
            {
                var cutoff = DateTime.UtcNow.AddDays(-30);
                _seenFiles = _seenFiles.Where(kv => kv.Value >= cutoff).ToDictionary(kv => kv.Key, kv => kv.Value);
                File.WriteAllText(_statePath, JsonSerializer.Serialize(_seenFiles));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not save file-risk state");
            }
        }
    }
}