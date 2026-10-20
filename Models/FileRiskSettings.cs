namespace EndpointSecurityAgent.Models
{
    public class FileRiskSettings
    {
        public List<string> WatchedFolders { get; set; } = new() { "Downloads", "Desktop", "Documents" };
        public int RecentFileWindowMinutes { get; set; } = 60;
        public long MaxHashSizeBytes { get; set; } = 52428800; // 50 MB - skip hashing above this
        public string KnownMaliciousHashesPath { get; set; } = "KnownMaliciousHashes.json";
        public string StateFilePath { get; set; } = "filerisk_state.json";
    }
}