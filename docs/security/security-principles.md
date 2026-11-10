# VAJRA — Security Principles & Cryptographic Foundation

**Document Status:** Core Security Charter (Updated in Prompt 0002 — `FOUNDATION` & `SPECIFICATION`)

VAJRA is designed to protect personal devices owned or explicitly authorized by the user. Every architectural decision is governed by transparency, least privilege, hardware-backed cryptographic identity, and strict compliance with operating system security boundaries.

---

## 1. Authentication (Plane 1)

Detailed in [`docs/security/authentication.md`](./authentication.md):
- **Passkey-First & Mandatory MFA:** Supports FIDO2 / WebAuthn Passkeys (`uv = required`) and Argon2id passwords paired with mandatory TOTP / WebAuthn second factors.
- **Short-Lived Rotated Sessions:** Browser sessions (`__Host-vajra_session`) use 256-bit opaque tokens stored only as `SHA-256` hashes in `DeviceSession`, with a default 15-minute idle TTL (`SESSION_TTL_SECONDS = 900`), rolling token rotation, and instant server-side revocation.

---

## 2. Three-Plane Trust & Authorization Separation

Detailed in [`docs/security/remote-command-security.md`](./remote-command-security.md) and [`docs/security/authorization-matrix.md`](./authorization-matrix.md):

```text
Plane 1: User Authentication      ───►  Proves: "This is the human account owner."
Plane 2: Device Authentication    ───►  Proves: "This is the trusted hardware endpoint."
Plane 3: Command Authorization    ───►  Proves: "This specific user is authorized to perform
                                                 this specific allowlisted action on this
                                                 specific trusted device right now."
```

- **No Shared Credentials Across Planes:** User session cookies cannot submit device telemetry, and device keys cannot query console endpoints or issue commands to other devices.
- **Step-Up Command Authorization:** Sensitive remote commands (`RING_PHONE`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`, `REQUEST_LOCATION`) require an active Plane 1 session + fresh Step-Up Auth +Trusted Target Device + Allowlisted Command + 128-bit Nonce + Expiration TTL + synchronous `AuditLog` entry.

---

## 3. Encryption & Secret Hygiene

- **In Transit:** All communication between the Android App, Windows Agent, Web Console, and `vajra-api` uses **TLS 1.3**.
- **At Rest:** High-sensitivity physical coordinates in `LocationRecord` (`encryptedCoordinates`) and MFA TOTP seeds in `UserCredential` are encrypted at the application layer using **AES-256-GCM** with authenticated associated data (`AAD`) binding the record to the owning `userId` and `deviceId`.
- **Signed Commands & Receipts:** Every `RemoteCommand` is signed by the Backend Command Authority (`serverSignature`), and every `CommandResult` is signed by the endpoint device's private key (`deviceSignature`).
- **Pre-Storage Redaction:** Structured logs pass through `sanitizeLogMetadata()` (`@vajra/security`), and ThreatCheck URLs pass through `redactUrlSecrets()` so query tokens (`?token=SECRET`) are logged only as `?token=[REDACTED]`.

---

## 4. Hardware-Backed Device Identity (Plane 2)

Detailed in [`docs/security/device-enrollment.md`](./device-enrollment.md):

```text
Device ID (UUIDv4)  +  Public Key (Ed25519 / ECDSA P-256)  +  Cryptographic Proof & Metadata
```

- **Private Key Isolation:** Private keys are generated on-device inside **Windows TPM 2.0 / CNG** or the **Android Hardware-Backed Keystore** as non-exportable keys whenever supported by hardware.
- **Zero Private Key Transmission:** `vajra-api` stores only public keys (`DeviceCredential.publicKeyPem`) and never receives private keys.

---

## 5. Tamper-Evident Auditability

Detailed in [`docs/architecture/observability.md`](../architecture/observability.md):
- Every security-sensitive operation writes an append-only record to `AuditLog` linked via a cryptographic **SHA-256 hash chain** (`previousEntryHash -> entryHash`).
- Any unauthorized database modification or deletion of historical audit entries breaks the hash chain and is immediately detectable.

---

## 6. Ethical & Operating System Security Boundaries

Enforced in `@vajra/security` (`packages/security/src/index.ts`) and detailed in [`docs/platform/windows.md`](../platform/windows.md), [`docs/platform/android.md`](../platform/android.md), and [`docs/security/authorized-testing.md`](./authorized-testing.md):
- **Zero Spyware / Zero Surveillance:** No keylogging, password collection, credential theft, hidden microphone/webcam recording, or covert screen capture.
- **Zero OS or Antivirus Bypass:** No rootkits, no disabling Windows Defender, no privilege escalation, and no bypassing Android runtime permissions.
- **Zero Arbitrary Remote Execution:** Commands such as `EXECUTE_SHELL`, `EXECUTE_COMMAND`, `REMOTE_TERMINAL`, `UPLOAD_EXECUTABLE`, and `DOWNLOAD_AND_EXECUTE` are permanently prohibited.
- **Zero Unauthorized Intrusive Scanning:** ThreatCheck performs passive/reputation URL checks and prohibits unauthorized active vulnerability scanning.
