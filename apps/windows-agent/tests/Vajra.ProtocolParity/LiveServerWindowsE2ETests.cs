using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Vajra.WindowsAgent.Commands;
using Vajra.WindowsAgent.Crypto;
using Xunit;

namespace Vajra.ProtocolParity;

/// <summary>
/// Live HTTP + PostgreSQL end-to-end verification of the Windows agent cryptographic protocol,
/// enrollment, Plane-2 request signing, heartbeat persistence, command lifecycle, event upload,
/// replay/tamper/timestamp defenses, and permanent revocation against the real VAJRA server.
///
/// Activated when VAJRA_LIVE_API_URL is set (mandatory when VAJRA_REQUIRE_LIVE_E2E=1).
/// </summary>
public class LiveServerWindowsE2ETests
{
    [Fact]
    public async Task WindowsAgent_FullLifecycleAgainstLivePostgreSqlServer()
    {
        var baseUrl = Environment.GetEnvironmentVariable("VAJRA_LIVE_API_URL")?.Trim().TrimEnd('/');
        var requireLive = Environment.GetEnvironmentVariable("VAJRA_REQUIRE_LIVE_E2E") == "1";

        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            Assert.False(requireLive, "VAJRA_REQUIRE_LIVE_E2E=1 was set, but VAJRA_LIVE_API_URL is empty.");
            return;
        }

        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler { CookieContainer = cookies, UseCookies = true };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        // 1. Verify live PostgreSQL readiness
        using (var readyRes = await http.GetAsync($"{baseUrl}/api/ready"))
        {
            Assert.Equal(HttpStatusCode.OK, readyRes.StatusCode);
            using var readyDoc = JsonDocument.Parse(await readyRes.Content.ReadAsStringAsync());
            var backend = readyDoc.RootElement
                .GetProperty("checks")
                .GetProperty("identityStore")
                .GetProperty("backend")
                .GetString();
            Assert.Equal("postgresql", backend);
        }

        // 2. Register a dedicated disposable owner account
        var uniqueSuffix = Guid.NewGuid().ToString("N")[..10];
        var ownerEmail = $"win-e2e-{uniqueSuffix}@vajra.test";
        string csrfToken;
        using (var regRes = await PostJsonAsync(http, $"{baseUrl}/api/auth/register", new
        {
            email = ownerEmail,
            displayName = "Windows Agent E2E Verifier",
            password = "Correct-Horse-Battery-99!Staple",
        }, csrf: null))
        {
            Assert.Equal(HttpStatusCode.Created, regRes.StatusCode);
            using var regDoc = JsonDocument.Parse(await regRes.Content.ReadAsStringAsync());
            csrfToken = regDoc.RootElement.GetProperty("csrfToken").GetString()!;
            Assert.False(string.IsNullOrWhiteSpace(csrfToken));
        }

        using (var meRes = await http.GetAsync($"{baseUrl}/api/auth/me"))
        {
            Assert.Equal(HttpStatusCode.OK, meRes.StatusCode);
        }

        // 3. Enable TOTP MFA so we can exercise real step-up protected revocation later
        string totpSecretBase32;
        using (var mfaSetupRes = await PostJsonAsync(http, $"{baseUrl}/api/auth/mfa/setup", new { }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.OK, mfaSetupRes.StatusCode);
            using var mfaDoc = JsonDocument.Parse(await mfaSetupRes.Content.ReadAsStringAsync());
            totpSecretBase32 = mfaDoc.RootElement.GetProperty("secretBase32").GetString()!;
        }

        using (var mfaVerifyRes = await PostJsonAsync(http, $"{baseUrl}/api/auth/mfa/verify", new
        {
            code = ComputeTotpCode(totpSecretBase32),
        }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.OK, mfaVerifyRes.StatusCode);
        }

        // 4. Plane-1 initiate WINDOWS device enrollment
        string deviceId;
        string enrollmentToken;
        string challengeNonce;
        using (var initRes = await PostJsonAsync(http, $"{baseUrl}/api/devices/enrollment/initiate", new
        {
            name = "WIN11-WORKSTATION-E2E",
            deviceType = "WINDOWS",
            osVersion = "Windows 11 Pro 23H2",
        }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.Created, initRes.StatusCode);
            using var initDoc = JsonDocument.Parse(await initRes.Content.ReadAsStringAsync());
            deviceId = initDoc.RootElement.GetProperty("device").GetProperty("id").GetString()!;
            var enrollEl = initDoc.RootElement.GetProperty("enrollment");
            enrollmentToken = enrollEl.GetProperty("enrollmentToken").GetString()!;
            challengeNonce = enrollEl.GetProperty("challengeNonce").GetString()!;
        }

        // 5. Generate real .NET ECDSA P-256 device keypair and submit signed PoP
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spkiDer = deviceKey.ExportSubjectPublicKeyInfo();
        var fingerprint = "sha256:" + Convert.ToHexString(SHA256.HashData(spkiDer)).ToLowerInvariant();
        var publicKeyPem = ToPem("PUBLIC KEY", spkiDer);

        var enrollTs = DeviceRequestSigner.UtcTimestampIso();
        var clientNonce = DeviceRequestSigner.NewNonce();
        var enrollTranscript = DeviceRequestSigner.BuildEnrollmentTranscript(
            deviceId, enrollmentToken, challengeNonce, fingerprint, enrollTs, clientNonce);
        var enrollSig = DeviceRequestSigner.SignTranscript(enrollTranscript, deviceKey);

        using (var submitRes = await PostJsonAsync(http, $"{baseUrl}/api/devices/enrollment/submit", new
        {
            enrollmentToken,
            publicKeyPem,
            keyAlgorithm = "ECDSA_P256",
            signatureBase64 = enrollSig,
            timestampIso = enrollTs,
            clientNonce,
        }, csrf: null))
        {
            Assert.Equal(HttpStatusCode.OK, submitRes.StatusCode);
            using var subDoc = JsonDocument.Parse(await submitRes.Content.ReadAsStringAsync());
            Assert.Equal(
                "KEY_SUBMITTED_AWAITING_OWNER_CONFIRMATION",
                subDoc.RootElement.GetProperty("status").GetString());
        }

        // 6. Plane-2 request BEFORE owner confirmation must fail with 403 DEVICE_NOT_TRUSTED
        using (var preConfirmHb = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, new { connectivityStatus = "ONLINE", agentVersion = "0.1.0-windows" }))
        {
            Assert.Equal(HttpStatusCode.Forbidden, preConfirmHb.StatusCode);
            var errCode = GetErrorCode(await preConfirmHb.Content.ReadAsStringAsync());
            Assert.Equal("DEVICE_NOT_TRUSTED", errCode);
        }

        // 7. Owner confirms enrollment -> TRUSTED
        using (var confirmRes = await PostJsonAsync(
            http, $"{baseUrl}/api/devices/{deviceId}/enrollment/confirm",
            new { publicKeyFingerprint = fingerprint }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.OK, confirmRes.StatusCode);
            using var confDoc = JsonDocument.Parse(await confirmRes.Content.ReadAsStringAsync());
            Assert.Equal("TRUSTED", confDoc.RootElement.GetProperty("device").GetProperty("lifecycleState").GetString());
        }

        // 8. Signed Windows heartbeat (omits batteryLevel & charging; updates state to ACTIVE)
        var fixedNonce = DeviceRequestSigner.NewNonce();
        var fixedTs = DeviceRequestSigner.UtcTimestampIso();
        var hbBody = new
        {
            connectivityStatus = "ONLINE",
            agentVersion = "0.1.0-windows",
            osVersion = "Microsoft Windows 10.0.22631",
            platform = "WINDOWS",
        };
        using (var hbRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, hbBody, overrideTimestamp: fixedTs, overrideNonce: fixedNonce))
        {
            Assert.Equal(HttpStatusCode.OK, hbRes.StatusCode);
            using var hbDoc = JsonDocument.Parse(await hbRes.Content.ReadAsStringAsync());
            var hbEl = hbDoc.RootElement.GetProperty("heartbeat");
            Assert.Equal(JsonValueKind.Null, hbEl.GetProperty("batteryLevel").ValueKind);
            Assert.Equal(JsonValueKind.Null, hbEl.GetProperty("charging").ValueKind);
        }

        // Windows battery-history endpoint must return 400 UNSUPPORTED_PLATFORM
        using (var winBatRes = await http.GetAsync($"{baseUrl}/api/devices/{deviceId}/battery-history"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, winBatRes.StatusCode);
            Assert.Equal("UNSUPPORTED_PLATFORM", GetErrorCode(await winBatRes.Content.ReadAsStringAsync()));
        }

        // 9. Replay nonce rejection (409 DEVICE_NONCE_REPLAYED)
        using (var replayRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, hbBody, overrideTimestamp: fixedTs, overrideNonce: fixedNonce))
        {
            Assert.Equal(HttpStatusCode.Conflict, replayRes.StatusCode);
            Assert.Equal("DEVICE_NONCE_REPLAYED", GetErrorCode(await replayRes.Content.ReadAsStringAsync()));
        }

        // 10. Expired timestamp rejection (401 DEVICE_TIMESTAMP_EXPIRED)
        var staleTs = DateTime.UtcNow.AddMinutes(-5).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
        using (var staleRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, hbBody, overrideTimestamp: staleTs))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, staleRes.StatusCode);
            Assert.Equal("DEVICE_TIMESTAMP_EXPIRED", GetErrorCode(await staleRes.Content.ReadAsStringAsync()));
        }

        // 11. Tampered body rejection (401 INVALID_DEVICE_SIGNATURE)
        using (var tamperRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, hbBody,
            tamperedWireBodyJson: """{"connectivityStatus":"OFFLINE","agentVersion":"tampered"}"""))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, tamperRes.StatusCode);
            Assert.Equal("INVALID_DEVICE_SIGNATURE", GetErrorCode(await tamperRes.Content.ReadAsStringAsync()));
        }

        // 12. Unsupported non-allowlisted command rejected without being queued (400 UNSUPPORTED_DEVICE_ACTION)
        using (var badCmdRes = await PostJsonAsync(
            http, $"{baseUrl}/api/devices/{deviceId}/commands",
            new { actionType = "RUN_POWERSHELL" }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, badCmdRes.StatusCode);
            Assert.Equal("UNSUPPORTED_DEVICE_ACTION", GetErrorCode(await badCmdRes.Content.ReadAsStringAsync()));
        }

        using (var listCmdEmpty = await http.GetAsync($"{baseUrl}/api/devices/{deviceId}/commands"))
        {
            Assert.Equal(HttpStatusCode.OK, listCmdEmpty.StatusCode);
            using var listDoc = JsonDocument.Parse(await listCmdEmpty.Content.ReadAsStringAsync());
            Assert.Equal(0, listDoc.RootElement.GetProperty("commands").GetArrayLength());
        }

        // 13. Queue REQUEST_DEVICE_STATUS -> poll -> acknowledge -> complete receipt -> verify immutability
        string commandId;
        using (var createCmdRes = await PostJsonAsync(
            http, $"{baseUrl}/api/devices/{deviceId}/commands",
            new { actionType = CommandCapabilityMatrix.RequestDeviceStatus }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.Created, createCmdRes.StatusCode);
            using var createDoc = JsonDocument.Parse(await createCmdRes.Content.ReadAsStringAsync());
            var cmdEl = createDoc.RootElement.GetProperty("command");
            commandId = cmdEl.GetProperty("id").GetString()!;
            Assert.Equal("QUEUED", cmdEl.GetProperty("status").GetString());
        }

        using (var pollRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Get, $"/api/devices/{deviceId}/commands/pending",
            deviceId, deviceKey, body: null))
        {
            Assert.Equal(HttpStatusCode.OK, pollRes.StatusCode);
            using var pollDoc = JsonDocument.Parse(await pollRes.Content.ReadAsStringAsync());
            var cmds = pollDoc.RootElement.GetProperty("commands");
            Assert.Equal(1, cmds.GetArrayLength());
            Assert.Equal(commandId, cmds[0].GetProperty("id").GetString());
            Assert.Equal("DELIVERED", cmds[0].GetProperty("status").GetString());
        }

        using (var ackRes = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/commands/{commandId}/acknowledge",
            deviceId, deviceKey, new { }))
        {
            Assert.Equal(HttpStatusCode.OK, ackRes.StatusCode);
            using var ackDoc = JsonDocument.Parse(await ackRes.Content.ReadAsStringAsync());
            Assert.Equal("ACKNOWLEDGED", ackDoc.RootElement.GetProperty("command").GetProperty("status").GetString());
        }

        Assert.True(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.RequestDeviceStatus));
        var resultPayload = new
        {
            status = "COMPLETED",
            safeMessage = "Windows agent status report completed.",
            resultMetadata = new
            {
                agentVersion = "0.1.0-windows",
                architecture = "X64",
            },
        };
        using (var resSubmit = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/commands/{commandId}/result",
            deviceId, deviceKey, resultPayload))
        {
            Assert.Equal(HttpStatusCode.OK, resSubmit.StatusCode);
            using var resDoc = JsonDocument.Parse(await resSubmit.Content.ReadAsStringAsync());
            Assert.False(resDoc.RootElement.GetProperty("idempotentReplay").GetBoolean());
            Assert.Equal("COMPLETED", resDoc.RootElement.GetProperty("command").GetProperty("status").GetString());
        }

        // Duplicate identical result returns idempotentReplay=true
        using (var dupSubmit = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/commands/{commandId}/result",
            deviceId, deviceKey, resultPayload))
        {
            Assert.Equal(HttpStatusCode.OK, dupSubmit.StatusCode);
            using var dupDoc = JsonDocument.Parse(await dupSubmit.Content.ReadAsStringAsync());
            Assert.True(dupDoc.RootElement.GetProperty("idempotentReplay").GetBoolean());
        }

        // 14. Signed Windows Agent Event Upload (AGENT_STARTED, WINDOWS_EVENT_LOG, AGENT_STOPPED)
        foreach (var evt in new object[]
        {
            new
            {
                category = "Device",
                type = "AGENT_STARTED",
                severity = "INFO",
                title = "Windows agent started",
                description = "VAJRA Windows agent 0.1.0-windows is running.",
                source = "WINDOWS_AGENT",
                metadata = new { agentVersion = "0.1.0-windows" },
            },
            new
            {
                category = "Device",
                type = "WINDOWS_EVENT_LOG",
                severity = "WARNING",
                title = "Windows System: Service Control Manager",
                description = "Sample bounded Windows event log upload test.",
                source = "WINDOWS_AGENT",
                metadata = new { logName = "System", eventId = 7036, level = "Warning" },
            },
            new
            {
                category = "Device",
                type = "AGENT_STOPPED",
                severity = "INFO",
                title = "Windows agent stopped",
                description = "VAJRA Windows agent is shutting down.",
                source = "WINDOWS_AGENT",
            },
        })
        {
            using var evtRes = await SendPlane2Async(
                http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/events",
                deviceId, deviceKey, evt);
            Assert.Equal(HttpStatusCode.Created, evtRes.StatusCode);
        }

        using (var eventsListRes = await http.GetAsync($"{baseUrl}/api/events?deviceId={deviceId}"))
        {
            Assert.Equal(HttpStatusCode.OK, eventsListRes.StatusCode);
            var eventsJson = await eventsListRes.Content.ReadAsStringAsync();
            Assert.Contains("AGENT_STARTED", eventsJson);
            Assert.Contains("WINDOWS_EVENT_LOG", eventsJson);
            Assert.Contains("AGENT_STOPPED", eventsJson);
        }

        // 15. Step-up MFA + Permanent Device Revocation -> subsequent Plane-2 requests rejected
        using (var stepUpRes = await PostJsonAsync(http, $"{baseUrl}/api/auth/step-up", new
        {
            actionScope = "DEVICE_REVOKE",
            totpCode = ComputeTotpCode(totpSecretBase32),
        }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.OK, stepUpRes.StatusCode);
        }

        using (var revokeRes = await PostJsonAsync(
            http, $"{baseUrl}/api/devices/{deviceId}/revoke",
            new { reason = "WINDOWS_E2E_VERIFICATION_COMPLETE" }, csrfToken))
        {
            Assert.Equal(HttpStatusCode.OK, revokeRes.StatusCode);
            using var revDoc = JsonDocument.Parse(await revokeRes.Content.ReadAsStringAsync());
            Assert.Equal("REVOKED", revDoc.RootElement.GetProperty("device").GetProperty("lifecycleState").GetString());
        }

        using (var postRevokeHb = await SendPlane2Async(
            http, baseUrl, HttpMethod.Post, $"/api/devices/{deviceId}/heartbeat",
            deviceId, deviceKey, hbBody))
        {
            Assert.Equal(HttpStatusCode.Forbidden, postRevokeHb.StatusCode);
            Assert.Equal("DEVICE_REVOKED", GetErrorCode(await postRevokeHb.Content.ReadAsStringAsync()));
        }

        // 16. Verify PostgreSQL append-only audit hash chain integrity
        using (var auditRes = await http.GetAsync($"{baseUrl}/api/audit"))
        {
            Assert.Equal(HttpStatusCode.OK, auditRes.StatusCode);
            using var auditDoc = JsonDocument.Parse(await auditRes.Content.ReadAsStringAsync());
            Assert.True(auditDoc.RootElement.GetProperty("chainVerification").GetProperty("valid").GetBoolean());
        }
    }

    private static async Task<HttpResponseMessage> PostJsonAsync(
        HttpClient http,
        string url,
        object body,
        string? csrf)
    {
        var json = JsonSerializer.Serialize(body);
        var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        if (!string.IsNullOrWhiteSpace(csrf))
        {
            req.Headers.TryAddWithoutValidation("X-CSRF-Token", csrf);
        }
        return await http.SendAsync(req);
    }

    private static async Task<HttpResponseMessage> SendPlane2Async(
        HttpClient http,
        string baseUrl,
        HttpMethod method,
        string path,
        string deviceId,
        ECDsa key,
        object? body,
        string? overrideTimestamp = null,
        string? overrideNonce = null,
        string? tamperedWireBodyJson = null)
    {
        var bodyJson = DeviceRequestSigner.SerializeBody(body);
        var ts = overrideTimestamp ?? DeviceRequestSigner.UtcTimestampIso();
        var nonce = overrideNonce ?? DeviceRequestSigner.NewNonce();
        var transcript = DeviceRequestSigner.BuildTranscript(method.Method, path, deviceId, ts, nonce, bodyJson);
        var sig = DeviceRequestSigner.SignTranscript(transcript, key);

        var req = new HttpRequestMessage(method, baseUrl + path);
        req.Headers.TryAddWithoutValidation("X-Vajra-Device-Id", deviceId);
        req.Headers.TryAddWithoutValidation("X-Vajra-Timestamp", ts);
        req.Headers.TryAddWithoutValidation("X-Vajra-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Vajra-Signature", sig);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (method != HttpMethod.Get)
        {
            req.Content = new StringContent(tamperedWireBodyJson ?? bodyJson, Encoding.UTF8, "application/json");
        }
        return await http.SendAsync(req);
    }

    private static string GetErrorCode(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("error").GetProperty("code").GetString() ?? "";
    }

    private static string ToPem(string label, byte[] der)
    {
        var b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");
        for (var i = 0; i < b64.Length; i += 64)
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }

    private static string ComputeTotpCode(string secretBase32)
    {
        var keyBytes = Base32Decode(secretBase32);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(keyBytes);
        var hash = hmac.ComputeHash(counterBytes);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);
        var otp = binary % 1_000_000;
        return otp.ToString("D6");
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleaned = input.Trim().TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var ch in cleaned)
        {
            var val = alphabet.IndexOf(ch);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return output.ToArray();
    }
}
