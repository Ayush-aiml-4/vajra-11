using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Events;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;

namespace Vajra.WindowsAgent.Workers;

public sealed class EventUploadWorker : BackgroundService
{
    private readonly AgentOptions _options;
    private readonly DeviceIdentityStore _store;
    private readonly VajraApiClient _api;
    private readonly WindowsEventCollector _collector;
    private readonly ILogger<EventUploadWorker> _logger;
    private bool _startupSent;

    public EventUploadWorker(
        AgentOptions options,
        DeviceIdentityStore store,
        VajraApiClient api,
        WindowsEventCollector collector,
        ILogger<EventUploadWorker> logger)
    {
        _options = options;
        _store = store;
        _api = api;
        _collector = collector;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(_options.EventCollectIntervalSeconds, 30, 600));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!_store.HasIdentity)
                {
                    await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (!_startupSent)
                {
                    await TrySendAsync(new
                    {
                        category = "Device",
                        type = "AGENT_STARTED",
                        severity = "INFO",
                        title = "Windows agent started",
                        description = $"VAJRA Windows agent {_options.AgentVersion} is running.",
                        source = "WINDOWS_AGENT",
                        metadata = new
                        {
                            agentVersion = _options.AgentVersion,
                            os = RuntimeInformation.OSDescription,
                        },
                    }, stoppingToken).ConfigureAwait(false);
                    _startupSent = true;
                }

                if (OperatingSystem.IsWindows())
                {
                    var batch = _collector.CollectNew(10);
                    foreach (var ev in batch)
                    {
                        await TrySendAsync(new
                        {
                            category = ev.Category,
                            type = ev.Type,
                            severity = ev.Severity,
                            title = ev.Title,
                            description = ev.Description,
                            occurredAt = ev.OccurredAt.ToString("o"),
                            source = "WINDOWS_AGENT",
                            metadata = ev.Metadata,
                        }, stoppingToken).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Event upload cycle error.");
            }

            await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
        }

        // Best-effort shutdown event (may be cancelled)
        try
        {
            if (_store.HasIdentity)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await TrySendAsync(new
                {
                    category = "Device",
                    type = "AGENT_STOPPED",
                    severity = "INFO",
                    title = "Windows agent stopped",
                    description = "VAJRA Windows agent is shutting down.",
                    source = "WINDOWS_AGENT",
                }, cts.Token).ConfigureAwait(false);
            }
        }
        catch { /* ignore on shutdown */ }
    }

    private async Task TrySendAsync(object body, CancellationToken ct)
    {
        try
        {
            using var res = await _api.SubmitEventAsync(body, ct).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
                _logger.LogDebug("Event upload status {Status}", (int)res.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Event upload failed.");
        }
    }
}
