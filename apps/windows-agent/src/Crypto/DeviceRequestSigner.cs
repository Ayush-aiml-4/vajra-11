using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vajra.WindowsAgent.Crypto;

/// <summary>
/// Plane-2 request signing compatible with packages/security device-identity.ts:
/// Transcript = "VAJRA-DEVICE-AUTH-V1"|METHOD|path|deviceId|timestampIso|nonce|sha256hex(canonicalBody)
/// Body canonicalization: JSON with sorted object keys (matching server canonicalJsonSerialize).
/// </summary>
public static class DeviceRequestSigner
{
    private static readonly JsonSerializerOptions CompactJson = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ComputeBodySha256Hex(string? rawJsonBody)
    {
        var payload = string.IsNullOrEmpty(rawJsonBody) ? "{}" : rawJsonBody;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Serialize an object to compact JSON. Prefer pre-built JSON strings for exact byte control.
    /// </summary>
    public static string SerializeBody(object? body)
    {
        if (body is null) return "{}";
        if (body is string s)
            return string.IsNullOrEmpty(s) ? "{}" : CanonicalizeJsonString(s);
        // Serialize then re-canonicalize so key order matches server canonicalJsonSerialize
        var json = JsonSerializer.Serialize(body, CompactJson);
        return CanonicalizeJsonString(json);
    }

    /// <summary>
    /// Recursive key-sorted JSON matching packages/security canonicalJsonSerialize.
    /// </summary>
    public static string CanonicalizeJsonString(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return "{}";
        using var doc = JsonDocument.Parse(json);
        return CanonicalizeElement(doc.RootElement);
    }

    private static string CanonicalizeElement(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var props = el.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).ToList();
                var parts = props.Select(p =>
                    $"{JsonSerializer.Serialize(p.Name)}:{CanonicalizeElement(p.Value)}");
                return "{" + string.Join(",", parts) + "}";
            }
            case JsonValueKind.Array:
            {
                var parts = el.EnumerateArray().Select(CanonicalizeElement);
                return "[" + string.Join(",", parts) + "]";
            }
            case JsonValueKind.String:
                return JsonSerializer.Serialize(el.GetString());
            case JsonValueKind.Number:
                return el.GetRawText(); // preserve JSON number text
            case JsonValueKind.True:
                return "true";
            case JsonValueKind.False:
                return "false";
            case JsonValueKind.Null:
            default:
                return "null";
        }
    }

    public static string BuildTranscript(
        string method,
        string path,
        string deviceId,
        string timestampIso,
        string nonce,
        string bodyJson)
    {
        var payloadHash = ComputeBodySha256Hex(bodyJson);
        return string.Join('|',
            "VAJRA-DEVICE-AUTH-V1",
            method.Trim().ToUpperInvariant(),
            path.Trim(),
            deviceId.Trim(),
            timestampIso.Trim(),
            nonce.Trim(),
            payloadHash);
    }

    public static string SignTranscript(string transcript, ECDsa privateKey)
    {
        var bytes = Encoding.UTF8.GetBytes(transcript);
        // .NET returns IEEE P1363; Node crypto.verify expects DER for ECDSA
        var p1363 = privateKey.SignData(bytes, HashAlgorithmName.SHA256);
        var der = EcdsaSignatureFormat.P1363ToDer(p1363);
        return Convert.ToBase64String(der);
    }

    public static string NewNonce()
    {
        var buf = new byte[24];
        RandomNumberGenerator.Fill(buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }

    public static string UtcTimestampIso() =>
        DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");

    /// <summary>
    /// Enrollment PoP: "VAJRA-ENROLL-V1"|deviceId|TOKEN_UPPER|challengeNonce|fingerprint|timestamp|clientNonce
    /// </summary>
    public static string BuildEnrollmentTranscript(
        string deviceId,
        string enrollmentToken,
        string challengeNonce,
        string publicKeyFingerprint,
        string timestampIso,
        string clientNonce)
    {
        return string.Join('|',
            "VAJRA-ENROLL-V1",
            deviceId.Trim(),
            enrollmentToken.Trim().ToUpperInvariant(),
            challengeNonce.Trim(),
            publicKeyFingerprint.Trim(),
            timestampIso.Trim(),
            clientNonce.Trim());
    }
}
