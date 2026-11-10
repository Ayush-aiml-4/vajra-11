# VAJRA Windows Agent (`apps/windows-agent`)

**Status:** Foundation implementation (Prompt 0014)  
**Target:** .NET 8 Windows Worker Service (`net8.0-windows`)  
**Service name:** `VajraGuardService` (display: VAJRA Personal Security Guard)

This agent enrolls a Windows PC with the existing VAJRA backend using **ECDSA P-256**, signs Plane-2 requests with the same transcript format as `packages/security` (`VAJRA-DEVICE-AUTH-V1`), and supports heartbeat, pending-command polling, limited command execution (`REQUEST_DEVICE_STATUS`), and bounded event-log collection.

## Prerequisites

- Windows 10 22H2+ or Windows 11 (x64 or ARM64)
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build
- Reachable VAJRA API (`ServerBaseUrl`)
- Owner account in the web console to **initiate** and **confirm** enrollment

Optional for broader event logs: membership in **Event Log Readers** (Security log is not required for the initial collector).

## Build

```powershell
cd apps/windows-agent
dotnet restore
dotnet build -c Release
```

## Configuration

`appsettings.json` section `VajraAgent`, or environment:

| Variable | Purpose |
| :--- | :--- |
| `VAJRA_SERVER_BASE_URL` | Backend origin (e.g. `https://vajra.example.com`) |
| `VAJRA_DATA_DIRECTORY` | Override data dir (default `%ProgramData%\VAJRA\WindowsAgent`) |

**Private keys** are stored as DPAPI-protected PKCS#8 under the data directory (`device-key.bin`). They are never uploaded.

## Enrollment (manual, explicit)

1. In the web console: open **Connect Device**, choose **Windows**, and click **Continue to Pairing**.
2. Click **Copy Windows Agent Command** (or **Copy Pairing Bundle**).
3. On the Windows PC:

```powershell
# Using direct CLI flags (copied from the web console):
dotnet run -- enroll --server "https://vajra.example.com" --token <TOKEN> --device-id <UUID> --challenge-nonce <HEX>

# Or using a Pairing Bundle JSON string or file path:
dotnet run -- enroll --bundle C:\Temp\vajra-pairing-bundle.json
```

4. In the console: **Approve Device** so lifecycle becomes `TRUSTED`.
5. Run the agent; the first signed heartbeat transitions the device to `ACTIVE` and `ONLINE` on the server.

```powershell
dotnet run -- status
dotnet run
```

## Release Packaging & Windows Service Lifecycle (`scripts/*.ps1`)

Explicit owner-administered PowerShell helpers are provided under `apps/windows-agent/scripts/` alongside `appsettings.Production.json`:

```powershell
# 1. Build release binaries (win-x64 or win-arm64) + print SHA-256 hash
.\scripts\publish-release.ps1 -RuntimeIdentifier win-x64

# 2. Install VajraGuardService (elevated PowerShell; sets %ProgramData%\VAJRA\WindowsAgent ACLs & SCM crash recovery)
.\scripts\install-service.ps1 -PublishDirectory .\artifacts\publish\win-x64 -ServerBaseUrl "https://vajra.example.com"

# 3. Upgrade binaries in place while preserving DPAPI device-key.bin
.\scripts\upgrade-service.ps1 -PublishDirectory .\artifacts\publish\win-x64

# 4. Uninstall cleanly (-PurgeState optional to delete local DPAPI identity)
.\scripts\uninstall-service.ps1
```

Do **not** use silent installers that hide the service. Stopping/uninstall uses standard SCM tools (`services.msc`, `sc.exe`, or `Stop-Service`).

## Command capability matrix

| Action | Agent behavior |
| :--- | :--- |
| `REQUEST_DEVICE_STATUS` | **Supported** — returns OS/agent metadata via signed result |
| `REQUEST_LOCATION` | Rejected — no GPS claim |
| `RING_DEVICE` | Rejected — not applicable to PC in this version |
| `DISPLAY_RECOVERY_MESSAGE` | Rejected — no desktop lock UI yet |
| `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` | Rejected locally — server-side lifecycle only |
| Arbitrary shell / PowerShell from server | **Never implemented** |

## Event collection

- Allowlisted logs: **Application**, **System** (bounded query + checkpoint file)
- Types: agent start/stop, Windows event-log summaries
- Does **not** collect keystrokes, passwords, cookies, screenshots, mic/camera, or personal files
- Does **not** silently enable audit policies

## Network behavior

- All Plane-2 calls: headers `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`
- Fresh nonce per request; TLS validation **enabled** (default `HttpClient`)
- Server base URL comes from config/identity only — **not** from remote commands
- Backoff on failures; no tight spin loop

## Limitations

- Not built/run in CI environments without .NET Windows SDK
- Ed25519 not used (ECDSA P-256 matches backend `ECDSA_P256`)
- Full TPM non-exportable CNG keys are a documented enhancement path; current store uses DPAPI LocalMachine
- Android lost-mode / ring semantics are out of scope for this agent

## Protocol alignment (Prompt 0016)

- ECDSA signatures are converted from IEEE P1363 to **DER** before Base64 (Node `crypto.verify` compatibility).
- Request bodies are **canonical JSON** (sorted keys) before SHA-256, matching `canonicalJsonSerialize`.
- See `docs/architecture/device-protocol-matrix.md`.
