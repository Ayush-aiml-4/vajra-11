# VAJRA — Remote Command Security & Three-Plane Trust Architecture

**Document Status:** Security Architecture Specification (Prompts 0007, 0008, 0011D — `IMPLEMENTED`)  
**Related Documents:** `docs/security/security-principles.md`, `docs/security/authorization-matrix.md`, `docs/architecture/failure-model.md`, `src/server/events/engine.ts`, `src/server/notifications/routes.ts`

---

## 1. The Three-Plane Trust Model

VAJRA enforces strict architectural separation between three independent verification planes. Compromising or authenticating on one plane never grants implicit authority on another.

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ PLANE 1: USER AUTHENTICATION                                               │
│ Proves: "This is the legitimate human account owner."                      │
│ Mechanisms: WebAuthn Passkey / Argon2id Password + Mandatory MFA           │
│ Output: Short-lived HTTP-only User Session                                 │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ PLANE 3: COMMAND AUTHORIZATION (THE BRIDGE)                                │
│ Proves: "This specific authenticated user is authorized to perform this    │
│          specific allowlisted action on this specific trusted device NOW." │
│ Mechanisms: Step-Up Auth Assertion + Ownership Check + Allowlist Check +   │
│             Cryptographic Nonce + Short Expiration + Server Signature +    │
│             Immutable AuditLog Record                                      │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ PLANE 2: DEVICE AUTHENTICATION                                             │
│ Proves: "This is the genuine enrolled hardware endpoint."                  │
│ Mechanisms: Device ID + Hardware-Backed Public Key + Signed Challenge/Proof│
│ Output: Verified Telemetry Ingestion & Signed Command Execution Receipt    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Strict Remote Command Allowlist

Remote commands in VAJRA are restricted to a fixed, compiled enumeration of safe, transparent device-recovery and status-verification operations.

### 2.1 Permitted Remote Commands (`Allowlist`)

| Command Identifier | Target Platform | Step-Up Auth Required? | Purpose & Permitted Behavior |
| :--- | :--- | :---: | :--- |
| **`REQUEST_DEVICE_STATUS`** | Windows, Android | No (Standard Session) | Requests an immediate signed heartbeat containing online status, battery level, network type, and security posture summary. |
| **`REQUEST_LOCATION`** | Windows, Android | Yes (Step-Up MFA / Passkey) | Requests an immediate permission-aware location check (`LocationSource`, `LocationAccuracy`, `Timestamp`, `PermissionState`). |
| **`RING_PHONE`** | Android | Yes (Step-Up MFA / Passkey) | Triggers an audible alert on the user's Android phone using standard Android audio/notification APIs so a misplaced phone can be found nearby. |
| **`ENABLE_LOST_MODE`** | Android (Primary), Windows (Status Flag) | Yes (Step-Up MFA / Passkey) | Transitions device to `LOST` state, enables periodic permitted location updates, and activates the Custom Recovery Screen on Android. |
| **`DISABLE_LOST_MODE`** | Android, Windows | Yes (Step-Up MFA / Passkey) | Deactivates Lost Mode, removes the Custom Recovery Screen, and returns the device to `TRUSTED`/`ACTIVE` state. |
| **`DISPLAY_RECOVERY_MESSAGE`** | Android | Yes (Step-Up MFA / Passkey) | Updates the structured owner contact details and recovery message displayed on the Android Custom Recovery Screen while in Lost Mode. |

### 2.2 Permanently Prohibited Commands (`Never Implemented`)

The following command types are **structurally banned** in `@vajra/security` and must never be added to `vajra-api`, the Windows Agent, or the Android App:

- ❌ `EXECUTE_SHELL` (No PowerShell, `cmd.exe`, bash, or sh execution)
- ❌ `EXECUTE_COMMAND` (No arbitrary OS process spawning)
- ❌ `REMOTE_TERMINAL` (No interactive shell or remote desktop control)
- ❌ `UPLOAD_EXECUTABLE` (No pushing binaries, scripts, or DLLs to devices)
- ❌ `DOWNLOAD_AND_EXECUTE` (No remote dropper functionality)
- ❌ Any command that captures audio, camera feeds, screenshots, keystrokes, or arbitrary files.

---

## 3. Canonical Remote Command Envelope

Every remote command created by `vajra-api` and delivered to a device must include all ten mandatory security fields:

```json
{
  "commandId": "cmd_01J9Z9A2B4C6D8E0F2G4H6J8K0",
  "targetDeviceId": "dev_3f8b2a10-5c4d-4e6a-9b8c-77889900aabb",
  "requesterUserId": "usr_94a1c02e-7b1a-4c9f-8e2d-112233445566",
  "commandType": "RING_PHONE",
  "parameters": {
    "durationSeconds": 60
  },
  "issuedAt": "2026-10-06T18:15:00.000Z",
  "expiresAt": "2026-10-06T18:20:00.000Z",
  "nonce": "b7f9d2e4a1c385096e4b2d1f8a7c9e02",
  "authorizationProof": {
    "stepUpVerified": true,
    "stepUpMethod": "PASSKEY_ASSERTION",
    "verifiedAt": "2026-10-06T18:14:58.210Z",
    "auditLogId": "aud_01J9Z9A2B0X1Y2Z3W4V5U6T7S8"
  },
  "serverSignature": "Ed25519Sig:MEUCIQD8..."
}
```

### 3.1 Field-by-Field Requirements

1. **`Command ID` (`commandId`)**: Globally unique identifier for tracking lifecycle and matching `CommandResult`.
2. **`Target Device` (`targetDeviceId`)**: Explicit UUID of the enrolled device. Must belong to `requesterUserId` and be in `TRUSTED`, `ACTIVE`, `OFFLINE`, or `LOST` state (never `REVOKED` or `COMPROMISED`).
3. **`Requester` (`requesterUserId`)**: Authenticated owner ID who initiated the action.
4. **`Timestamp` (`issuedAt`)**: Server UTC timestamp when the command was authorized.
5. **`Nonce` (`nonce`)**: At least 128 bits (16 bytes hex/base64) of cryptographically secure random data (`crypto.randomBytes(16)`), unique across all commands.
6. **`Expiration` (`expiresAt`)**: Strict TTL boundary:
   - Immediate interactive commands (`RING_PHONE`, `REQUEST_DEVICE_STATUS`, `REQUEST_LOCATION`): default **5 minutes** (`300 seconds`).
   - Lost-mode activation commands (`ENABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`) queued for an offline device: configurable up to **24 hours**, re-signed upon dispatch.
7. **`Authorization` (`authorizationProof`)**: References the verified step-up authentication challenge and the pre-execution `AuditLog` record ID.
8. **`Signature` (`serverSignature`)**: Detached cryptographic signature produced by the Backend Command Authority signing key over the canonical byte representation of `(commandId || targetDeviceId || requesterUserId || commandType || canonicalJson(parameters) || issuedAt || expiresAt || nonce)`.
9. **`Execution Result` (`CommandResult`)**: Signed receipt returned by the target device after processing:
   - `commandId`, `deviceId`, `status` (`COMPLETED`, `FAILED`, `REJECTED_EXPIRED`, `REJECTED_INVALID_SIGNATURE`, `OS_PERMISSION_DENIED`), `executedAt`, `resultMetadata`, and `deviceSignature` (signed by the device's hardware-backed private key).
10. **`Audit Record` (`AuditLog`)**: Both command issuance (`COMMAND_ISSUED`) and result receipt (`COMMAND_RESULT_RECORDED`) are logged in the hash-chained `AuditLog`.

---

## 4. Multi-Layer Replay Protection

To defend against **Threat 8 (Replay of an Old Remote Command)** documented in `docs/security/threat-model.md`, VAJRA implements defense-in-depth replay prevention on both the server and the endpoint agent:

1. **Unique Nonce Constraint (Server & Agent):**
   - `RemoteCommand.nonce` has a `UNIQUE` index in PostgreSQL.
   - Each Windows and Android agent maintains a persistent local ring buffer (stored in protected app storage) of the last `1,000` executed `(commandId, nonce)` pairs. If an incoming command carries a `commandId` or `nonce` already present in the local ring buffer, the agent immediately drops it and reports a `REPLAY_ATTEMPT_DETECTED` security event.
2. **Strict Expiration Window (`expiresAt`):**
   - Before executing any command, the endpoint agent checks `currentDeviceUtcTime <= command.expiresAt` and `currentDeviceUtcTime >= command.issuedAt - 120s` (allowing for minor clock skew). Any expired command is rejected without execution.
3. **Target Binding (`targetDeviceId`):**
   - Because `targetDeviceId` is included inside the signed transcript covered by `serverSignature`, an attacker cannot take a valid `RING_PHONE` command meant for Device A and replay it against Device B.
4. **Signed Execution Receipt (`CommandResult`):**
   - Once a device returns a signed `CommandResult` for `commandId`, the backend transitions the command status to terminal (`COMPLETED` or `FAILED`) and never re-queues it.
