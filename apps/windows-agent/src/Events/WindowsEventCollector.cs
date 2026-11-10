using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;

namespace Vajra.WindowsAgent.Events;

/// <summary>
/// Collects a bounded allowlist of Windows event-log records the account may read.
/// Does not enable audit policies, does not collect keystrokes/screenshots/passwords.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventCollector
{
    private readonly AgentOptions _options;
    private readonly ILogger<WindowsEventCollector> _logger;
    private readonly string _checkpointPath;

    // Allowlisted providers / log names only
    private static readonly string[] AllowedLogs = { "System", "Application" };

    public WindowsEventCollector(AgentOptions options, ILogger<WindowsEventCollector> logger)
    {
        _options = options;
        _logger = logger;
        _checkpointPath = Path.Combine(options.ResolveDataDirectory(), "event-checkpoint.json");
    }

    public IReadOnlyList<CollectedEvent> CollectNew(int maxEvents = 20)
    {
        var results = new List<CollectedEvent>();
        var checkpoint = LoadCheckpoint();
        var newest = checkpoint;

        foreach (var logName in AllowedLogs)
        {
            try
            {
                // Only Information/Warning/Error from last window; no Security log unless reader group present
                var query = $"*[System[TimeCreated[@SystemTime>'{checkpoint:yyyy-MM-ddTHH:mm:ss.fffZ}'] and (Level=1 or Level=2 or Level=3 or Level=4)]]";
                using var reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, query));
                for (var i = 0; i < maxEvents; i++)
                {
                    using var rec = reader.ReadEvent();
                    if (rec is null) break;

                    var created = rec.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
                    if (created > newest) newest = created;

                    var level = rec.LevelDisplayName ?? "Information";
                    var provider = rec.ProviderName ?? logName;
                    var message = SafeTruncate(rec.FormatDescription() ?? "(no description)", 400);

                    results.Add(new CollectedEvent
                    {
                        Category = "Device",
                        Type = "WINDOWS_EVENT_LOG",
                        Severity = MapSeverity(level),
                        Title = $"Windows {logName}: {provider}",
                        Description = message,
                        OccurredAt = created,
                        Metadata = new Dictionary<string, object?>
                        {
                            ["logName"] = logName,
                            ["provider"] = provider,
                            ["eventId"] = rec.Id,
                            ["level"] = level,
                        },
                    });
                }
            }
            catch (EventLogException ex)
            {
                _logger.LogDebug("Event log {Log} not readable: {Message}", logName, ex.Message);
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogDebug("Insufficient rights to read event log {Log}.", logName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Collector error for log {Log}.", logName);
            }
        }

        if (newest > checkpoint)
            SaveCheckpoint(newest);

        return results;
    }

    private DateTime LoadCheckpoint()
    {
        try
        {
            if (File.Exists(_checkpointPath))
            {
                var json = File.ReadAllText(_checkpointPath);
                var dto = JsonSerializer.Deserialize<CheckpointDto>(json);
                if (dto?.Utc is not null)
                    return dto.Utc.Value.UtcDateTime;
            }
        }
        catch { /* start fresh */ }
        return DateTime.UtcNow.AddMinutes(-15);
    }

    private void SaveCheckpoint(DateTime utc)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_checkpointPath)!);
            File.WriteAllText(_checkpointPath, JsonSerializer.Serialize(new CheckpointDto { Utc = utc }));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to persist event checkpoint.");
        }
    }

    private static string MapSeverity(string level) => level.ToLowerInvariant() switch
    {
        "critical" or "error" => "HIGH",
        "warning" => "WARNING",
        _ => "INFO",
    };

    private static string SafeTruncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private sealed class CheckpointDto
    {
        public DateTimeOffset? Utc { get; set; }
    }
}

public sealed class CollectedEvent
{
    public string Category { get; set; } = "Device";
    public string Type { get; set; } = "WINDOWS_EVENT_LOG";
    public string Severity { get; set; } = "INFO";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime OccurredAt { get; set; }
    public Dictionary<string, object?> Metadata { get; set; } = new();
}
