using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vajra.WindowsAgent.Configuration;

namespace Vajra.WindowsAgent.Identity;

public sealed class DeviceIdentityRecord
{
    public string DeviceId { get; set; } = "";
    public string KeyAlgorithm { get; set; } = "ECDSA_P256";
    public string PublicKeyPem { get; set; } = "";
    public string PublicKeyFingerprint { get; set; } = "";
    public string LifecycleState { get; set; } = "ENROLLMENT_PENDING";
    public string ServerBaseUrl { get; set; } = "";
    public DateTimeOffset? EnrolledAt { get; set; }
    public DateTimeOffset? LastConfirmedAt { get; set; }
}

/// <summary>
/// Stores public identity metadata as JSON and private key PKCS#8 bytes protected with DPAPI (LocalMachine).
/// Private keys are never logged or uploaded.
/// </summary>
public sealed class DeviceIdentityStore
{
    private readonly AgentOptions _options;
    private readonly ILogger<DeviceIdentityStore> _logger;
    private readonly object _gate = new();

    public DeviceIdentityStore(AgentOptions options, ILogger<DeviceIdentityStore> logger)
    {
        _options = options;
        _logger = logger;
    }

    private string Dir => _options.ResolveDataDirectory();
    private string IdentityPath => Path.Combine(Dir, "identity.json");
    private string KeyPath => Path.Combine(Dir, "device-key.bin");

    public bool HasIdentity
    {
        get
        {
            lock (_gate)
                return File.Exists(IdentityPath) && File.Exists(KeyPath);
        }
    }

    public DeviceIdentityRecord? LoadIdentity()
    {
        lock (_gate)
        {
            if (!File.Exists(IdentityPath)) return null;
            var json = File.ReadAllText(IdentityPath, Encoding.UTF8);
            return JsonSerializer.Deserialize<DeviceIdentityRecord>(json);
        }
    }

    public ECDsa LoadPrivateKeyEcdsa()
    {
        lock (_gate)
        {
            if (!File.Exists(KeyPath))
                throw new InvalidOperationException("Device private key not found. Complete enrollment first.");
            var protectedBytes = File.ReadAllBytes(KeyPath);
            var pkcs8 = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.LocalMachine);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            CryptographicOperations.ZeroMemory(pkcs8);
            return ecdsa;
        }
    }

    public (DeviceIdentityRecord identity, ECDsa key) CreateNewEcdsaIdentity(string serverBaseUrl)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Dir);

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var publicDer = ecdsa.ExportSubjectPublicKeyInfo();
            var privatePkcs8 = ecdsa.ExportPkcs8PrivateKey();
            var fingerprint = "sha256:" + Convert.ToHexString(SHA256.HashData(publicDer)).ToLowerInvariant();
            var publicPem = ToPem("PUBLIC KEY", publicDer);

            var protectedKey = ProtectedData.Protect(privatePkcs8, optionalEntropy: null, DataProtectionScope.LocalMachine);
            CryptographicOperations.ZeroMemory(privatePkcs8);

            // Temporary device id placeholder until enrollment submit binds server id
            var record = new DeviceIdentityRecord
            {
                DeviceId = "",
                KeyAlgorithm = "ECDSA_P256",
                PublicKeyPem = publicPem,
                PublicKeyFingerprint = fingerprint,
                LifecycleState = "UNREGISTERED",
                ServerBaseUrl = serverBaseUrl.TrimEnd('/'),
            };

            File.WriteAllBytes(KeyPath, protectedKey);
            File.WriteAllText(IdentityPath, JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));

            // Return a live key instance for immediate use
            var live = ECDsa.Create();
            var again = ProtectedData.Unprotect(File.ReadAllBytes(KeyPath), null, DataProtectionScope.LocalMachine);
            live.ImportPkcs8PrivateKey(again, out _);
            CryptographicOperations.ZeroMemory(again);

            _logger.LogInformation("Generated new ECDSA P-256 device key (fingerprint {Fingerprint}). Private key stored via DPAPI.", fingerprint);
            return (record, live);
        }
    }

    public void SaveIdentity(DeviceIdentityRecord record)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(IdentityPath, JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    public void ClearIdentity()
    {
        lock (_gate)
        {
            if (File.Exists(IdentityPath)) File.Delete(IdentityPath);
            if (File.Exists(KeyPath)) File.Delete(KeyPath);
        }
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
}
