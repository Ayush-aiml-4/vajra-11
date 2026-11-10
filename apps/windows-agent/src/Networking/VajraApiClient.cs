using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Crypto;
using Vajra.WindowsAgent.Identity;

namespace Vajra.WindowsAgent.Networking;

/// <summary>
/// Typed client for Plane-2 device endpoints. Signs every request; never logs signatures or private material.
/// </summary>
public sealed class VajraApiClient
{
    private readonly HttpClient _http;
    private readonly AgentOptions _options;
    private readonly DeviceIdentityStore _store;
    private readonly ILogger<VajraApiClient> _logger;

    public VajraApiClient(
        HttpClient http,
        AgentOptions options,
        DeviceIdentityStore store,
        ILogger<VajraApiClient> logger)
    {
        _http = http;
        _options = options;
        _store = store;
        _logger = logger;
        _http.Timeout = TimeSpan.FromSeconds(Math.Clamp(options.HttpTimeoutSeconds, 5, 120));
    }

    public async Task<HttpResponseMessage> SendSignedAsync(
        HttpMethod method,
        string relativePath,
        object? body,
        CancellationToken ct)
    {
        var identity = _store.LoadIdentity()
            ?? throw new InvalidOperationException("Device is not enrolled.");
        if (string.IsNullOrWhiteSpace(identity.DeviceId))
            throw new InvalidOperationException("DeviceId missing; complete enrollment submit first.");

        // Never allow remote commands to redirect the base URL
        var baseUrl = string.IsNullOrWhiteSpace(identity.ServerBaseUrl)
            ? _options.ServerBaseUrl.TrimEnd('/')
            : identity.ServerBaseUrl.TrimEnd('/');

        var path = relativePath.StartsWith('/') ? relativePath : "/" + relativePath;
        var bodyJson = DeviceRequestSigner.SerializeBody(body);
        var timestamp = DeviceRequestSigner.UtcTimestampIso();
        var nonce = DeviceRequestSigner.NewNonce();
        var transcript = DeviceRequestSigner.BuildTranscript(
            method.Method, path, identity.DeviceId, timestamp, nonce, bodyJson);

        string signatureBase64;
        using (var key = _store.LoadPrivateKeyEcdsa())
        {
            signatureBase64 = DeviceRequestSigner.SignTranscript(transcript, key);
        }

        var request = new HttpRequestMessage(method, baseUrl + path);
        request.Headers.TryAddWithoutValidation("X-Vajra-Device-Id", identity.DeviceId);
        request.Headers.TryAddWithoutValidation("X-Vajra-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-Vajra-Nonce", nonce);
        request.Headers.TryAddWithoutValidation("X-Vajra-Signature", signatureBase64);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (method != HttpMethod.Get)
        {
            request.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");
        }

        _logger.LogDebug("Plane-2 {Method} {Path} (device {DeviceId})", method.Method, path, identity.DeviceId);
        return await _http.SendAsync(request, ct).ConfigureAwait(false);
    }

    public Task<HttpResponseMessage> HeartbeatAsync(object payload, CancellationToken ct) =>
        SendSignedAsync(HttpMethod.Post, $"/api/devices/{RequireDeviceId()}/heartbeat", payload, ct);

    public Task<HttpResponseMessage> GetPendingCommandsAsync(CancellationToken ct) =>
        SendSignedAsync(HttpMethod.Get, $"/api/devices/{RequireDeviceId()}/commands/pending", null, ct);

    public Task<HttpResponseMessage> AcknowledgeCommandAsync(string commandId, CancellationToken ct) =>
        SendSignedAsync(HttpMethod.Post, $"/api/devices/{RequireDeviceId()}/commands/{commandId}/acknowledge", new { }, ct);

    public Task<HttpResponseMessage> SubmitCommandResultAsync(string commandId, object result, CancellationToken ct) =>
        SendSignedAsync(HttpMethod.Post, $"/api/devices/{RequireDeviceId()}/commands/{commandId}/result", result, ct);

    public Task<HttpResponseMessage> SubmitEventAsync(object evt, CancellationToken ct) =>
        SendSignedAsync(HttpMethod.Post, $"/api/devices/{RequireDeviceId()}/events", evt, ct);

    /// <summary>Enrollment submit is unauthenticated (token + PoP); not Plane-2 signed.</summary>
    public async Task<HttpResponseMessage> EnrollmentSubmitAsync(object body, CancellationToken ct)
    {
        var baseUrl = _options.ServerBaseUrl.TrimEnd('/');
        var json = DeviceRequestSigner.SerializeBody(body);
        var request = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/api/devices/enrollment/submit")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        return await _http.SendAsync(request, ct).ConfigureAwait(false);
    }

    private string RequireDeviceId()
    {
        var id = _store.LoadIdentity()?.DeviceId;
        if (string.IsNullOrWhiteSpace(id))
            throw new InvalidOperationException("DeviceId not available.");
        return id;
    }
}
