using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Crypto;
using Vajra.WindowsAgent.Identity;
using Vajra.WindowsAgent.Networking;

namespace Vajra.WindowsAgent.Hosting;

/// <summary>
/// Interactive enrollment: requires a one-time token + challenge from the web console (Plane 1 initiate).
/// Owner must confirm enrollment in the console after submit (Plane 1 confirm → TRUSTED).
/// </summary>
public static class EnrollmentCli
{
    public static async Task<int> RunAsync(
        AgentOptions options,
        DeviceIdentityStore store,
        VajraApiClient api,
        ILogger logger,
        string[] args,
        CancellationToken ct)
    {
        // Args: enroll [--server <url>] [--bundle <json-or-file>] [--token <token> --device-id <uuid> --challenge-nonce <hex>]
        string? serverOverride = null;
        string? bundleArg = null;
        string? token = null;
        string? deviceId = null;
        string? challengeNonce = null;
        string? expiresAtIso = null;

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--server" && i + 1 < args.Length) serverOverride = args[++i];
            else if (args[i] == "--bundle" && i + 1 < args.Length) bundleArg = args[++i];
            else if (args[i] == "--token" && i + 1 < args.Length) token = args[++i];
            else if (args[i] == "--device-id" && i + 1 < args.Length) deviceId = args[++i];
            else if (args[i] == "--challenge-nonce" && i + 1 < args.Length) challengeNonce = args[++i];
        }

        if (!string.IsNullOrWhiteSpace(bundleArg))
        {
            if (!TryParsePairingBundle(
                bundleArg,
                out var bundleServer,
                out var bundleToken,
                out var bundleDeviceId,
                out var bundleNonce,
                out var bundleExpiresAt,
                out var bundleError))
            {
                Console.Error.WriteLine($"Invalid pairing bundle: {bundleError}");
                return 2;
            }

            serverOverride ??= bundleServer;
            token ??= bundleToken;
            deviceId ??= bundleDeviceId;
            challengeNonce ??= bundleNonce;
            expiresAtIso ??= bundleExpiresAt;
        }

        if (!string.IsNullOrWhiteSpace(expiresAtIso) &&
            DateTimeOffset.TryParse(expiresAtIso, out var parsedExpiry) &&
            parsedExpiry <= DateTimeOffset.UtcNow)
        {
            Console.Error.WriteLine("Pairing bundle has expired. Initiate a fresh pairing code in the VAJRA web console.");
            return 2;
        }

        if (!string.IsNullOrWhiteSpace(serverOverride))
        {
            options.ServerBaseUrl = serverOverride.Trim().TrimEnd('/');
        }

        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(deviceId) ||
            string.IsNullOrWhiteSpace(challengeNonce))
        {
            Console.Error.WriteLine(
                "Usage: Vajra.WindowsAgent enroll [--server <URL>] (--bundle <JSON_OR_PATH> | --token <TOKEN> --device-id <UUID> --challenge-nonce <HEX>)");
            Console.Error.WriteLine(
                "Obtain the pairing bundle or CLI command from the VAJRA web console Connect Device dialog.");
            return 2;
        }

        if (!options.TryValidateServerBaseUrl(out _, out var urlError))
        {
            Console.Error.WriteLine($"Invalid configuration: {urlError}");
            return 2;
        }

        var (identity, key) = store.CreateNewEcdsaIdentity(options.ServerBaseUrl);
        identity.DeviceId = deviceId.Trim();
        store.SaveIdentity(identity);

        var timestamp = DeviceRequestSigner.UtcTimestampIso();
        var clientNonce = DeviceRequestSigner.NewNonce();
        var transcript = DeviceRequestSigner.BuildEnrollmentTranscript(
            deviceId, token, challengeNonce, identity.PublicKeyFingerprint, timestamp, clientNonce);
        var signature = DeviceRequestSigner.SignTranscript(transcript, key);
        key.Dispose();

        var body = new
        {
            enrollmentToken = token.Trim(),
            publicKeyPem = identity.PublicKeyPem,
            keyAlgorithm = "ECDSA_P256",
            signatureBase64 = signature,
            timestampIso = timestamp,
            clientNonce,
        };

        logger.LogInformation("Submitting enrollment PoP for device {DeviceId} (token redacted).", deviceId);
        try
        {
            using var response = await api.EnrollmentSubmitAsync(body, ct).ConfigureAwait(false);
            var responseText = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                store.ClearIdentity();
                logger.LogError("Enrollment submit failed: HTTP {Status}. Body length={Len}",
                    (int)response.StatusCode, responseText.Length);
                Console.Error.WriteLine($"Enrollment failed: HTTP {(int)response.StatusCode}");
                return 1;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            store.ClearIdentity();
            logger.LogError("Enrollment submit could not reach server: {Reason}", ex.GetType().Name);
            Console.Error.WriteLine($"Enrollment failed: {ex.Message}");
            return 1;
        }

        identity.LifecycleState = "ENROLLMENT_PENDING";
        identity.EnrolledAt = DateTimeOffset.UtcNow;
        store.SaveIdentity(identity);

        Console.WriteLine("Enrollment public key submitted successfully.");
        Console.WriteLine($"Device ID: {deviceId}");
        Console.WriteLine($"Fingerprint: {identity.PublicKeyFingerprint}");
        Console.WriteLine("Next step: confirm the device in the VAJRA web console (owner session).");
        Console.WriteLine("The agent will only fully operate after lifecycle reaches TRUSTED/ACTIVE.");
        return 0;
    }

    public static bool TryParsePairingBundle(
        string rawOrPath,
        out string? serverUrl,
        out string? token,
        out string? deviceId,
        out string? challengeNonce,
        out string? expiresAt,
        out string? error) =>
        PairingBundleParser.TryParse(
            rawOrPath,
            out serverUrl,
            out token,
            out deviceId,
            out challengeNonce,
            out expiresAt,
            out error);
}
