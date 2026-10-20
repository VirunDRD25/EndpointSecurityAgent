using System.Net.Http.Headers;
using System.Net.Http.Json;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Sends the device report to the central server's /api/device/report
/// endpoint over HTTPS, authenticated with a per-device enrollment token.
/// Register this via IHttpClientFactory (AddHttpClient) in Program.cs so
/// connections/TLS are pooled correctly instead of created per-call.
/// </summary>
public class ApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ApiClient> _logger;
    private readonly AgentSettings _settings;

    public ApiClient(HttpClient httpClient, ILogger<ApiClient> logger, IOptions<AgentSettings> settings)
    {
        _httpClient = httpClient;
        _logger = logger;
        _settings = settings.Value;

        _httpClient.BaseAddress = new Uri(_settings.ServerBaseUrl);
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<bool> SendReportAsync(DeviceReport report, CancellationToken ct)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "api/device/report")
            {
                Content = JsonContent.Create(report)
            };

            // Per-device bearer token, issued during enrollment (see Phase 2 API).
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _settings.ApiKeyOrDeviceToken);

            var response = await _httpClient.SendAsync(request, ct);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Report sent successfully. Risk score: {Score}", report.RiskScore);
                return true;
            }

            _logger.LogWarning("Server rejected report: {StatusCode} {Reason}", (int)response.StatusCode, response.ReasonPhrase);
            return false;
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("Report submission timed out or was cancelled");
            return false;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error while sending report — server may be unreachable. Will retry next cycle.");
            return false;
        }
    }
}
