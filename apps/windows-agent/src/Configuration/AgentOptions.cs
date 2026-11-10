namespace Vajra.WindowsAgent.Configuration;

/// <summary>
/// Agent configuration loaded from appsettings.json / environment variables.
/// ServerBaseUrl is fixed at install/config time — never overridden by remote commands.
/// </summary>
public sealed class AgentOptions
{
    public const string SectionName = "VajraAgent";

    /// <summary>Backend origin, e.g. https://vajra.example.com (no trailing slash).</summary>
    public string ServerBaseUrl { get; set; } = "http://127.0.0.1:3000";

    /// <summary>Directory for DPAPI-protected identity files (default: %ProgramData%\VAJRA\WindowsAgent).</summary>
    public string DataDirectory { get; set; } = string.Empty;

    public int HeartbeatIntervalSeconds { get; set; } = 60;
    public int CommandPollIntervalSeconds { get; set; } = 30;
    public int EventCollectIntervalSeconds { get; set; } = 120;
    public int HttpTimeoutSeconds { get; set; } = 30;
    public int MaxRetryBackoffSeconds { get; set; } = 120;

    /// <summary>Key algorithm: ECDSA_P256 (default, CNG-friendly) or ED25519 if platform supports it.</summary>
    public string KeyAlgorithm { get; set; } = "ECDSA_P256";

    public string AgentVersion { get; set; } = "0.1.0-windows";

    public string ResolveDataDirectory()
    {
        if (!string.IsNullOrWhiteSpace(DataDirectory))
            return DataDirectory;
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(programData, "VAJRA", "WindowsAgent");
    }

    public bool TryValidateServerBaseUrl(out Uri? uri, out string? error)
    {
        uri = null;
        error = null;

        if (string.IsNullOrWhiteSpace(ServerBaseUrl))
        {
            error = "ServerBaseUrl is empty.";
            return false;
        }

        if (!Uri.TryCreate(ServerBaseUrl.Trim(), UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            error = "ServerBaseUrl must be an absolute http:// or https:// URL.";
            return false;
        }

        var requireHttps = string.Equals(
            Environment.GetEnvironmentVariable("VAJRA_REQUIRE_HTTPS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

        if (requireHttps && parsed.Scheme != Uri.UriSchemeHttps && !parsed.IsLoopback)
        {
            error = "ServerBaseUrl must use https:// when VAJRA_REQUIRE_HTTPS=true on non-loopback hosts.";
            return false;
        }

        uri = parsed;
        return true;
    }
}
