# VAJRA — Android Companion Architecture

**Path:** `apps/android`  
**Status:** Prompt 0015 foundation

## Layers

| Layer | Responsibility |
| :--- | :--- |
| `crypto.DeviceRequestSigner` | Canonical transcripts + ECDSA-SHA256 |
| `identity.AndroidKeystoreIdentity` | Non-exportable P-256 key + meta prefs |
| `network.VajraApiClient` | OkHttp client; signed headers |
| `work.*` | WorkManager heartbeat + command poll |
| `commands.CommandCapabilityMatrix` | Allowlist |
| `ui.*` | Dashboard, enrollment, settings, privacy |

## Protocol parity

Identical to Windows agent / Node security package:

- Enrollment: `VAJRA-ENROLL-V1|…`
- Device auth: `VAJRA-DEVICE-AUTH-V1|METHOD|path|deviceId|ts|nonce|sha256hex(body)`
- Headers: `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`

## Dashboard honesty

Server `lastHeartbeatAt` / connectivity drive web console status. Local “active” only after successful heartbeat response.
