# VAJRA — Windows Agent Architecture

**Component:** `apps/windows-agent`  
**Status:** Foundation (Prompt 0014)  
**Runtime:** .NET 8 Worker Service (`Microsoft.Extensions.Hosting.WindowsServices`)

## Modules

| Area | Types |
| :--- | :--- |
| Configuration | `AgentOptions` |
| Identity | `DeviceIdentityStore` (DPAPI key blob + identity.json) |
| Crypto | `DeviceRequestSigner` (transcript parity with Node security package) |
| Networking | `VajraApiClient` |
| Workers | `HeartbeatWorker`, `CommandPollerWorker`, `EventUploadWorker` |
| Commands | `CommandCapabilityMatrix` |
| Events | `WindowsEventCollector` |
| Hosting | `EnrollmentCli`, `Program` |

## Protocol compatibility

- **Enrollment PoP:** `VAJRA-ENROLL-V1|deviceId|TOKEN|challengeNonce|fingerprint|timestamp|clientNonce` signed ECDSA-SHA256
- **Plane-2:** `VAJRA-DEVICE-AUTH-V1|METHOD|path|deviceId|timestamp|nonce|sha256hex(body)`
- **Headers:** `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`
- **Endpoints:** heartbeat, pending commands, acknowledge, result, events

## Trust flow

1. Owner initiates enrollment (browser session).
2. Agent submits public key + PoP (no session cookie).
3. Owner confirms → server `TRUSTED`.
4. Agent heartbeats / polls with signed requests.
5. Dashboard uses `lastHeartbeatAt` / connectivity — enrollment alone ≠ connected.

## Explicit non-goals

Kernel drivers, process injection, arbitrary RCE, keylogging, disabling Defender, silent firewall changes.
