# VAJRA — Secure Device Enrollment Architecture

**Document Status:** Security Architecture Specification (Prompt 0004 — `IMPLEMENTED`)  
**Related Documents:** `docs/architecture/device-lifecycle.md`, `docs/security/security-principles.md`, `docs/security/authentication.md`, `packages/security/src/device-identity.ts`, `src/server/devices/routes.ts`

---

## 1. Enrollment Design Principles

A device in VAJRA is never authenticated by static shared API keys, MAC addresses, or IP addresses. Every Windows PC and Android phone must establish a unique, asymmetric cryptographic identity (`Device ID + Public Key + Registration Metadata`) bound to the user's account through an explicit, user-confirmed ceremony.

1. **On-Device Key Generation:** The asymmetric keypair (`Ed25519` or `ECDSA P-256`) is generated directly on the endpoint device.
2. **Hardware-Backed Private Key Isolation:** Whenever supported by the host hardware, the private key is generated and stored as non-exportable inside **Windows TPM 2.0 / CNG** or the **Android Hardware-Backed Keystore**. The private key is **never** transmitted to `vajra-api`.
3. **Short-Lived Single-Use Enrollment Tokens:** Pairing tokens expire rapidly (`10 minutes`), are single-use, and are stored only as cryptographic hashes in PostgreSQL.
4. **Explicit Owner Confirmation:** A device does not become `TRUSTED` until the authenticated user confirms the enrollment and public key fingerprint.

---

## 2. End-to-End Enrollment Ceremony

```text
Authenticated User (Web Console)            VAJRA Backend (vajra-api)              Target Endpoint (Windows / Android)
───────────────┬───────────────             ────────────┬────────────              ─────────────────┬─────────────────
               │                                        │                                           │
               │ 1. Request Enrollment Token            │                                           │
               │    (Step-Up MFA / Passkey Verified)    │                                           │
               ├───────────────────────────────────────►│                                           │
               │                                        │ Create Device (ENROLLMENT_PENDING)        │
               │                                        │ Store SHA-256(enrollmentToken), TTL=10m   │
               │ 2. Return QR Code / Pairing Code       │                                           │
               │◄───────────────────────────────────────┤                                           │
               │                                        │                                           │
               │ 3. User enters Pairing Code or scans QR on Endpoint                                │
               ├────────────────────────────────────────┼──────────────────────────────────────────►│
               │                                        │                                           │ 4. Generate Keypair in
               │                                        │                                           │    TPM / Android Keystore
               │                                        │                                           │    Sign Challenge + Nonce
               │                                        │ 5. Submit Enrollment Request              │
               │                                        │    (Token + PublicKey + Signed Proof +    │
               │                                        │     OS Metadata + Nonce)                  │
               │                                        │◄──────────────────────────────────────────┤
               │                                        │                                           │
               │                                        │ 6. Verify Token TTL, Single-Use,          │
               │                                        │    & Verify Signature using PublicKey     │
               │ 7. Prompt User to Confirm Device       │                                           │
               │    (Display Name, OS, Key Fingerprint) │                                           │
               │◄───────────────────────────────────────┤                                           │
               │                                        │                                           │
               │ 8. User Confirms Enrollment            │                                           │
               ├───────────────────────────────────────►│                                           │
               │                                        │ Transition Device -> TRUSTED              │
               │                                        │ Write AuditLog (DEVICE_ENROLLED)          │
               │                                        │ 9. Return Signed Enrollment Certificate / │
               │                                        │    Device ID Confirmation                 │
               │                                        ├──────────────────────────────────────────►│
```

---

## 3. Enrollment Security Controls

### 3.1 Enrollment Token Specification
- **Entropy:** Minimum 128 bits of cryptographic randomness (`crypto.randomBytes(16)`), formatted either as a QR code payload for Android or a segmented high-entropy alphanumeric pairing code for Windows CLI/Service setup.
- **Storage:** Only `SHA-256(enrollmentToken)` is stored in the database.
- **Expiration (`TTL`):** Strictly **10 minutes** (`600 seconds`) from generation. Expired tokens are automatically rejected.
- **Single-Use & Attempt Cap:** Immediately invalidated upon the first valid key submission or after **3 failed submission attempts** to prevent brute-force guessing.

### 3.2 Proof-of-Possession & Replay Protection
When the device submits its `publicKeyPem` during Step 5, it must prove it actually possesses the corresponding private key and is not replaying a captured packet:
- The device signs a canonical enrollment transcript:
  $$\text{Transcript} = \text{SHA-256}(\text{"VAJRA-ENROLL-V1"} \parallel \text{enrollmentToken} \parallel \text{devicePublicKeyFingerprint} \parallel \text{timestamp} \parallel \text{clientNonce})$$
- The backend verifies:
  1. The signature over `Transcript` is mathematically valid using the submitted `publicKeyPem`.
  2. The `timestamp` is within $\pm 120\text{ seconds}$ of server UTC time.
  3. The `publicKeyFingerprint` (`SHA-256` of SPKI DER bytes) is not already registered to any active or revoked device.

### 3.3 Device Naming & Identification
- During enrollment, the user assigns a human-readable label (e.g., `ASUS TUF F16` or `Android Phone`).
- The agent also supplies read-only OS metadata (`osType`: `WINDOWS` | `ANDROID`, `osVersion`, `agentVersion`, `hardwareBackedKey: boolean`).
- Device names are sanitized against HTML/script injection and length-limited (`1–64 characters`).

---

## 4. Revocation, Re-Enrollment & Compromised-Device Handling

### 4.1 Device Revocation
- The user can revoke any device at any time from the Web Console (`Devices -> Revoke Device`) after completing step-up authentication.
- Revocation immediately sets `Device.lifecycleState = REVOKED` and marks all associated `DeviceCredential` records as `active = false, revokedAt = now()`.
- Any subsequent heartbeat or event signed by that key receives `403 Forbidden (DEVICE_REVOKED)`, instructing the local agent to halt network polling and clear its pairing state.

### 4.2 Re-Enrollment (OS Reinstall or Hardware Reset)
- If a user wipes and reinstalls Windows or factory-resets their Android phone, the hardware-bound private key is destroyed on the device.
- To re-enroll the device:
  1. The user revokes or archives the old device entry in the Web Console.
  2. The user initiates a fresh enrollment flow, generating a new keypair and a new `DeviceCredential` fingerprint.
  3. Old keys are never exported or backed up to cloud storage, ensuring forward security if backups are compromised.

### 4.3 Compromised-Device Handling
- If a device is suspected of local malware compromise or key tampering:
  1. The user (or the Risk Engine) transitions the device to `COMPROMISED`.
  2. In `COMPROMISED` state, the device cannot acknowledge alerts, cannot trigger cross-device actions, and its incoming telemetry is flagged as untrusted in the Security Timeline.
  3. The user is guided to isolate the device, revoke its VAJRA credential (`REVOKED`), remediate the OS offline, and perform a clean re-enrollment with a new keypair once verified clean.
