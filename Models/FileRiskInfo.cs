using System.Text.Json.Serialization;

namespace EndpointSecurityAgent.Models
{
    public class FileRiskInfo
    {
        [JsonPropertyName("fileName")]
        public string FileName { get; set; } = string.Empty;

        [JsonPropertyName("filePath")]
        public string FilePath { get; set; } = string.Empty;

        [JsonPropertyName("extension")]
        public string Extension { get; set; } = string.Empty;

        [JsonPropertyName("category")]
        public string Category { get; set; } = "Other";

        [JsonPropertyName("sizeBytes")]
        public long SizeBytes { get; set; }

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = string.Empty;

        [JsonPropertyName("createdUtc")]
        public DateTime CreatedUtc { get; set; }

        [JsonPropertyName("modifiedUtc")]
        public DateTime ModifiedUtc { get; set; }

        [JsonPropertyName("location")]
        public string Location { get; set; } = string.Empty;

        [JsonPropertyName("riskLevel")]
        public string RiskLevel { get; set; } = "Low";

        [JsonPropertyName("riskReasons")]
        public List<string> RiskReasons { get; set; } = new();
    }
}