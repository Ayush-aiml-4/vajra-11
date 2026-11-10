using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;

namespace Vajra.WindowsAgent.Workers;

/// <summary>
/// Periodic signed heartbeat. Updates server last-seen / connectivity without inventing security alerts.
/// </summary>
public sealed class HeartbeatWorker : BackgroundService
{
    private readonly AgentOptions _options;
    private readonly DeviceIdentityStore _store;
    private readonly VajraApiClient _api;
    private readonly ILogger<HeartbeatWorker> _logger;

    public HeartbeatWorker(
        AgentOptions options,
        DeviceIdentityStore store,
        VajraApiClient api,
        ILogger<HeartbeatWorker> logger)
    {
        _options = options;
        _store = store;
        _api = api;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = TimeSpan.FromSeconds(Math.Clamp(_options.HeartbeatIntervalSeconds, 15, 600));
        var backoff = TimeSpan.FromSeconds(5);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!_store.HasIdentity)
                {
                    _logger.LogDebug("Heartbeat skipped: device not enrolled.");
                    await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (! _options.TryValidateServerBaseUrl(out _, out var urlError))
                {
                    _logger.LogError("Heartbeat skipped: invalid ServerBaseUrl ({Error})", urlError);
                    await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                var identity = _store.LoadIdentity();
                if (identity is null ||
                    identity.LifecycleState is "UNREGISTERED" or "REVOKED" or "DECOMMISSIONED" or "COMPROMISED")
                {
                    _logger.LogWarning("Heartbeat skipped: lifecycle state {State}", identity?.LifecycleState);
                    await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                var payload = new
                {
                    connectivityStatus = "ONLINE",
                    agentVersion = _options.AgentVersion,
                    osVersion = RuntimeInformation.OSDescription,
                    platform = "WINDOWS",
                };

                using var response = await _api.HeartbeatAsync(payload, stoppingToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Heartbeat accepted ({StatusCode}).", (int)response.StatusCode);
                    backoff = TimeSpan.FromSeconds(5);
                    if (identity is not null &&
                        identity.LifecycleState is "ENROLLMENT_PENDING" or "TRUSTED" or "OFFLINE" or "ACTIVE")
                    {
                        identity.LifecycleState = "ACTIVE";
                        identity.LastConfirmedAt = DateTimeOffset.UtcNow;
                        _store.SaveIdentity(identity);
                    }
                }
                else if ((int)response.StatusCode is 401 or 403)
                {
                    _logger.LogError("Heartbeat rejected ({StatusCode}). Credential may be revoked.", (int)response.StatusCode);
                    backoff = TimeSpan.FromSeconds(Math.Min(_options.MaxRetryBackoffSeconds, backoff.TotalSeconds * 2));
                }
                else
                {
                    _logger.LogWarning("Heartbeat failed with status {StatusCode}.", (int)response.StatusCode);
                    backoff = TimeSpan.FromSeconds(Math.Min(_options.MaxRetryBackoffSeconds, backoff.TotalSeconds * 2));
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Heartbeat error (message only; no secrets).");
                backoff = TimeSpan.FromSeconds(Math.Min(_options.MaxRetryBackoffSeconds, Math.Max(5, backoff.TotalSeconds * 2)));
            }

            var wait = responseAwareWait(delay, backoff);
            await Task.Delay(wait, stoppingToken).ConfigureAwait(false);
        }
    }

    private static TimeSpan responseAwareWait(TimeSpan interval, TimeSpan backoff) =>
        backoff > interval ? backoff : interval;
}
