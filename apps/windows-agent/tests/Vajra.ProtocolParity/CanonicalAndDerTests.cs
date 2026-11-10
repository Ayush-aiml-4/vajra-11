using System.Security.Cryptography;
using System.Text;
using Vajra.WindowsAgent.Commands;
using Vajra.WindowsAgent.Configuration;
using Vajra.WindowsAgent.Crypto;
using Xunit;

namespace Vajra.ProtocolParity;

public class CanonicalAndDerTests
{
    [Fact]
    public void CanonicalJson_SortsObjectKeys_LikeServer()
    {
        var a = DeviceRequestSigner.CanonicalizeJsonString("""{"b":1,"a":2}""");
        var b = DeviceRequestSigner.CanonicalizeJsonString("""{"a":2,"b":1}""");
        Assert.Equal(a, b);
        Assert.Equal("""{"a":2,"b":1}""", a);
    }

    [Fact]
    public void BodyHash_EmptyObjectMatchesKnownSha256()
    {
        var h1 = DeviceRequestSigner.ComputeBodySha256Hex("{}");
        var h2 = DeviceRequestSigner.ComputeBodySha256Hex(null);
        Assert.Equal(h1, h2);
        Assert.Equal(64, h1.Length);
        Assert.Equal("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", h1);
    }

    [Fact]
    public void DeviceAuthTranscript_MatchesContract()
    {
        var bodyJson = DeviceRequestSigner.CanonicalizeJsonString(
            """{"agentVersion":"0.1.0","connectivityStatus":"ONLINE"}""");
        var t = DeviceRequestSigner.BuildTranscript(
            method: "post",
            path: "/api/devices/00000000-0000-4000-8000-000000000001/heartbeat",
            deviceId: "00000000-0000-4000-8000-000000000001",
            timestampIso: "2026-01-01T00:00:00.000Z",
            nonce: new string('n', 32),
            bodyJson: bodyJson);
        Assert.StartsWith(
            "VAJRA-DEVICE-AUTH-V1|POST|/api/devices/00000000-0000-4000-8000-000000000001/heartbeat|",
            t);
        var parts = t.Split('|');
        Assert.Equal(7, parts.Length);
    }

    [Fact]
    public void EnrollmentTranscript_UppercasesToken()
    {
        var t = DeviceRequestSigner.BuildEnrollmentTranscript(
            deviceId: "dev-1",
            enrollmentToken: "ab12cd",
            challengeNonce: "challenge",
            publicKeyFingerprint: "sha256:deadbeef",
            timestampIso: "2026-01-01T00:00:00.000Z",
            clientNonce: "clientnoncevalue12");
        Assert.StartsWith("VAJRA-ENROLL-V1|dev-1|AB12CD|challenge|", t);
    }

    [Fact]
    public void Ecdsa_P1363ToDer_IsVerifiableAsDer()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var data = Encoding.UTF8.GetBytes("VAJRA-DEVICE-AUTH-V1|POST|/api/x|id|ts|nonce|hash");
        var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256);
        Assert.Equal(64, p1363.Length);
        var der = EcdsaSignatureFormat.P1363ToDer(p1363);
        Assert.True(der.Length > 64);
        Assert.Equal(0x30, der[0]);
        Assert.True(ecdsa.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void SignTranscript_ProducesBase64DerNotRawP1363()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var transcript = "VAJRA-DEVICE-AUTH-V1|POST|/api/devices/x/heartbeat|x|2026-01-01T00:00:00.000Z|" +
                         new string('a', 32) + "|44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        var b64 = DeviceRequestSigner.SignTranscript(transcript, ecdsa);
        var der = Convert.FromBase64String(b64);
        Assert.Equal(0x30, der[0]);
        Assert.True(ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(transcript),
            der,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void CommandCapabilityMatrix_AllowsOnlyRequestDeviceStatusOnWindows()
    {
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.RequestDeviceStatus));
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.RingDevice));
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.RequestLocation));
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.DisplayRecoveryMessage));
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.EnableLostMode));
        Assert.True(CommandCapabilityMatrix.IsKnown(CommandCapabilityMatrix.DisableLostMode));
        Assert.False(CommandCapabilityMatrix.IsKnown("RUN_POWERSHELL"));

        Assert.True(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.RequestDeviceStatus));
        Assert.False(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.RingDevice));
        Assert.False(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.RequestLocation));
        Assert.False(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.DisplayRecoveryMessage));
        Assert.False(CommandCapabilityMatrix.IsExecutableOnWindows(CommandCapabilityMatrix.EnableLostMode));
        Assert.False(string.IsNullOrWhiteSpace(CommandCapabilityMatrix.UnsupportedReason(CommandCapabilityMatrix.RingDevice)));
    }

    [Fact]
    public void AgentOptions_TryValidateServerBaseUrl_RejectsInvalidSchemesAndEmpty()
    {
        var opts = new AgentOptions { ServerBaseUrl = "" };
        Assert.False(opts.TryValidateServerBaseUrl(out _, out var err1));
        Assert.False(string.IsNullOrWhiteSpace(err1));

        opts.ServerBaseUrl = "ftp://example.com";
        Assert.False(opts.TryValidateServerBaseUrl(out _, out _));

        opts.ServerBaseUrl = "not-a-uri";
        Assert.False(opts.TryValidateServerBaseUrl(out _, out _));

        opts.ServerBaseUrl = "http://127.0.0.1:3000";
        Assert.True(opts.TryValidateServerBaseUrl(out var loopbackUri, out var loopbackErr));
        Assert.Null(loopbackErr);
        Assert.NotNull(loopbackUri);

        opts.ServerBaseUrl = "https://vajra.example.com";
        Assert.True(opts.TryValidateServerBaseUrl(out var httpsUri, out _));
        Assert.NotNull(httpsUri);
    }

    [Fact]
    public void PairingBundleParser_ParsesConsoleBundleAndRejectsIncompleteJson()
    {
        var json = """
        {
          "version": 1,
          "origin": "https://guard.vajra.example",
          "deviceId": "00000000-0000-4000-8000-000000000099",
          "enrollmentToken": "VJR-ABCD-1234",
          "challengeNonce": "0123456789abcdef"
        }
        """;
        Assert.True(PairingBundleParser.TryParse(
            json,
            out var serverUrl,
            out var token,
            out var deviceId,
            out var nonce,
            out _,
            out var err));
        Assert.Null(err);
        Assert.Equal("https://guard.vajra.example", serverUrl);
        Assert.Equal("VJR-ABCD-1234", token);
        Assert.Equal("00000000-0000-4000-8000-000000000099", deviceId);
        Assert.Equal("0123456789abcdef", nonce);

        Assert.False(PairingBundleParser.TryParse("""{"deviceId":"only-id"}""", out _, out _, out _, out _, out _, out var missingErr));
        Assert.False(string.IsNullOrWhiteSpace(missingErr));
    }
}
