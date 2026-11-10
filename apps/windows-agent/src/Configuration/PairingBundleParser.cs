using System.Text;
using System.Text.Json;

namespace Vajra.WindowsAgent.Configuration;

/// <summary>
/// Portable JSON parser for VAJRA web console Pairing Bundles (`version: 1`).
/// Supports both inline JSON strings and local bundle file paths.
/// </summary>
public static class PairingBundleParser
{
    public static bool TryParse(
        string rawOrPath,
        out string? serverUrl,
        out string? token,
        out string? deviceId,
        out string? challengeNonce,
        out string? expiresAt,
        out string? error)
    {
        serverUrl = null;
        token = null;
        deviceId = null;
        challengeNonce = null;
        expiresAt = null;
        error = null;

        if (string.IsNullOrWhiteSpace(rawOrPath))
        {
            error = "Pairing bundle input is empty.";
            return false;
        }

        var trimmed = rawOrPath.Trim();
        var jsonPayload = trimmed;
        if (!trimmed.StartsWith('{'))
        {
            if (!File.Exists(trimmed))
            {
                error = "Expected JSON object or an existing bundle file path.";
                return false;
            }
            jsonPayload = File.ReadAllText(trimmed, Encoding.UTF8);
        }

        try
        {
            using var doc = JsonDocument.Parse(jsonPayload);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                error = "Pairing bundle root must be a JSON object.";
                return false;
            }

            var root = doc.RootElement;
            serverUrl = ReadOptionalString(root, "origin")
                        ?? ReadOptionalString(root, "serverBaseUrl")
                        ?? ReadOptionalString(root, "server");
            token = ReadOptionalString(root, "enrollmentToken")
                    ?? ReadOptionalString(root, "token");
            deviceId = ReadOptionalString(root, "deviceId");
            challengeNonce = ReadOptionalString(root, "challengeNonce");
            expiresAt = ReadOptionalString(root, "expiresAt");

            if (string.IsNullOrWhiteSpace(token) ||
                string.IsNullOrWhiteSpace(deviceId) ||
                string.IsNullOrWhiteSpace(challengeNonce))
            {
                error = "Pairing bundle must include token/enrollmentToken, deviceId, and challengeNonce.";
                return false;
            }

            return true;
        }
        catch (JsonException)
        {
            error = "Pairing bundle is not valid JSON.";
            return false;
        }
    }

    private static string? ReadOptionalString(JsonElement obj, string propName)
    {
        if (obj.TryGetProperty(propName, out var el) && el.ValueKind == JsonValueKind.String)
        {
            var value = el.GetString()?.Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        return null;
    }
}
