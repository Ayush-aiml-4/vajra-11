using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Commands;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;

namespace Vajra.WindowsAgent.Workers;

public sealed class CommandPollerWorker : BackgroundService
{
    private readonly AgentOptions _options;
    private readonly DeviceIdentityStore _store;
    private readonly VajraApiClient _api;
    private readonly ILogger<CommandPollerWorker> _logger;
    private readonly ConcurrentDictionary<string, byte> _processed = new();

    public CommandPollerWorker(
        AgentOptions options,
        DeviceIdentityStore store,
        VajraApiClient api,
        ILogger<CommandPollerWorker> logger)
    {
        _options = options;
        _store = store;
        _api = api;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(_options.CommandPollIntervalSeconds, 10, 300));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!_store.HasIdentity)
                {
                    await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                using var pendingRes = await _api.GetPendingCommandsAsync(stoppingToken).ConfigureAwait(false);
                if (!pendingRes.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Pending commands poll failed: {Status}", (int)pendingRes.StatusCode);
                    await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                await using var stream = await pendingRes.Content.ReadAsStreamAsync(stoppingToken).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: stoppingToken).ConfigureAwait(false);
                if (!doc.RootElement.TryGetProperty("commands", out var commands) &&
                    !doc.RootElement.TryGetProperty("pendingCommands", out commands))
                {
                    // Some responses nest under different keys; try root array
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        commands = doc.RootElement;
                    else if (doc.RootElement.TryGetProperty("pendingCommands", out var pc))
                        commands = pc;
                }

                if (commands.ValueKind == JsonValueKind.Array)
                {
                    foreach (var cmd in commands.EnumerateArray())
                    {
                        await ProcessCommandAsync(cmd, stoppingToken).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Command poll error.");
            }

            await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessCommandAsync(JsonElement cmd, CancellationToken ct)
    {
        var commandId = cmd.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
        var actionType = cmd.TryGetProperty("actionType", out var atEl) ? atEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(commandId) || string.IsNullOrWhiteSpace(actionType))
            return;

        if (!_processed.TryAdd(commandId, 0))
        {
            _logger.LogDebug("Skipping already processed command {CommandId}", commandId);
            return;
        }

        // Acknowledge first
        try
        {
            using var ack = await _api.AcknowledgeCommandAsync(commandId, ct).ConfigureAwait(false);
            if (!ack.IsSuccessStatusCode)
                _logger.LogWarning("Ack failed for {CommandId}: {Status}", commandId, (int)ack.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Ack error for {CommandId}", commandId);
        }

        string status;
        string safeMessage;
        object? metadata = null;

        if (!CommandCapabilityMatrix.IsKnown(actionType))
        {
            status = "FAILED";
            safeMessage = "Unknown action type rejected by Windows agent.";
        }
        else if (!CommandCapabilityMatrix.IsExecutableOnWindows(actionType))
        {
            status = "FAILED";
            safeMessage = CommandCapabilityMatrix.UnsupportedReason(actionType);
        }
        else if (actionType == CommandCapabilityMatrix.RequestDeviceStatus)
        {
            status = "COMPLETED";
            safeMessage = "Windows agent status report completed.";
            metadata = new
            {
                agentVersion = _options.AgentVersion,
                osDescription = RuntimeInformation.OSDescription,
                framework = RuntimeInformation.FrameworkDescription,
                architecture = RuntimeInformation.OSArchitecture.ToString(),
                machineName = Environment.MachineName,
            };
        }
        else
        {
            status = "FAILED";
            safeMessage = "No local handler.";
        }

        var resultBody = new
        {
            status,
            safeMessage,
            resultMetadata = metadata,
        };

        try
        {
            using var resultRes = await _api.SubmitCommandResultAsync(commandId, resultBody, ct).ConfigureAwait(false);
            if (resultRes.IsSuccessStatusCode)
                _logger.LogInformation("Result submitted for {CommandId}: {Status}", commandId, status);
            else
                _logger.LogWarning("Result submit failed for {CommandId}: {Code}", commandId, (int)resultRes.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Result submit error for {CommandId}", commandId);
            _processed.TryRemove(commandId, out _);
        }
    }
}
