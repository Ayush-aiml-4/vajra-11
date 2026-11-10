# VAJRA — Database Architecture & Detailed Entity Specification

**Database Engine:** PostgreSQL  
**ORM Direction:** Prisma ORM (`prisma/schema.prisma`)  
**Document Status:** Identity, Device Enrollment, Notification, SecurityEvent, CommandResult, DeviceHeartbeat, RiskAssessment & AuditLog `IMPLEMENTED` in `prisma/schema.prisma` (Prompts 0003–0008)

> **Implementation Status (Prompt 0008):**  
> - **`IMPLEMENTED` in Prisma Schema & Repository (`src/server/db/repository.ts`):** `User`, `UserCredential`, `Session`, `Device`, `DeviceCredential`, `DeviceEnrollmentChallenge`, `DeviceReplayNonce`, `Notification`, `SecurityEvent`, `DeviceActionCommand`, `CommandResult`, `DeviceHeartbeat`, `RiskAssessment`, `RecoveryMessageConfig`, and `AuditLog`.

---

## 1. Entity Relationship Diagram (Conceptual)

```text
User (1) ──────┬──────< (N) UserCredential       (Passkeys, Password Hash, MFA TOTP)
               ├──────< (N) DeviceSession        (Short-lived Web Console & API Sessions)
               ├──────< (1) RecoveryProfile      (Owner Alias & Contact Info for Lost Mode)
               ├──────< (N) ThreatCheck ────────< (N) ThreatIndicator
               ├──────< (N) AuditLog             (Tamper-Evident Hash-Chained Audit Trail)
               └──────< (N) Device
                              │
                              ├──────< (1..N) DeviceCredential  (Public Keys & Hardware Attestation)
                              ├──────< (0..N) SecurityEvent
                              ├──────< (0..N) Alert
                              ├──────< (0..N) LocationRecord    (Permission-Gated & Encrypted)
                              ├──────< (0..N) RiskAssessment    (Explainable 0–100 Risk Breakdown)
                              └──────< (0..N) RemoteCommand ──── (0..1) CommandResult
```

---

## 2. Detailed Entity Specifications (15 Entities)

### 2.1 `User`
- **Purpose:** Represents the human account owner managing their personal devices.
- **Important Fields:**
  - `id` (UUID, PK)
  - `email` (String, Unique, Normalized lowercase)
  - `displayName` (String, 1–64 chars)
  - `accountStatus` (`ACTIVE` | `LOCKED` | `PENDING_DELETION`)
  - `createdAt`, `updatedAt`, `lastLoginAt` (Timestamp UTC)
- **Relationships:** `1:N` with `UserCredential`, `DeviceSession`, `Device`, `ThreatCheck`, `AuditLog`; `1:1` with `RecoveryProfile`.
- **Sensitive Fields:** `email` (PII).
- **Retention Considerations:** Retained while account is active; hard-deleted upon user account deletion request.

---

### 2.2 `UserCredential`
- **Purpose:** Stores authentication authenticators for Plane 1 (User Authentication), separating credential material from the core `User` profile and supporting multiple WebAuthn Passkeys plus MFA.
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `credentialType` (`WEBAUTHN_PASSKEY` | `PASSWORD_ARGON2ID` | `TOTP_MFA` | `RECOVERY_CODE_HASH`)
  - `webauthnCredentialId` (Bytes/Base64URL, Nullable, Unique)
  - `webauthnPublicKey` (Bytes, Nullable)
  - `webauthnCounter` (BigInt, Nullable — clone detection)
  - `secretHash` (String, Nullable — Argon2id hash for passwords or SHA-256 hash for recovery codes)
  - `encryptedTotpSecret` (Bytes, Nullable — AES-256-GCM encrypted TOTP seed)
  - `label` (String, e.g., `"YubiKey 5C"`, `"Windows Hello"`)
  - `createdAt`, `lastUsedAt`, `revokedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User`.
- **Sensitive Fields:** `secretHash`, `encryptedTotpSecret`. Plaintext passwords, raw recovery codes, or unencrypted TOTP seeds are **never** stored.
- **Retention Considerations:** Revoked credentials retained for 30 days for security audit visibility, then purged.

---

### 2.3 `Device`
- **Purpose:** Represents a personal endpoint (Windows PC/laptop or Android phone) enrolled in VAJRA.
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `name` (String, e.g., `"ASUS TUF F16"`, `"Android Phone"`)
  - `deviceType` (`WINDOWS` | `ANDROID`)
  - `lifecycleState` (`ENROLLMENT_PENDING` | `TRUSTED` | `ACTIVE` | `OFFLINE` | `LOST` | `COMPROMISED` | `REVOKED` | `DECOMMISSIONED`)
  - `connectivityStatus` (`ONLINE` | `OFFLINE` | `UNKNOWN`)
  - `osVersion` (String), `agentVersion` (String)
  - `currentRiskScore` (Int, `0–100`), `currentRiskLevel` (`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `locationPermissionState` (`GRANTED_BACKGROUND` | `GRANTED_FOREGROUND_ONLY` | `DENIED` | `OS_DISABLED`)
  - `lastHeartbeatAt`, `enrolledAt`, `revokedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User`; `1:N` with `DeviceCredential`, `SecurityEvent`, `Alert`, `LocationRecord`, `RemoteCommand`, `RiskAssessment`.
- **Sensitive Fields:** `name` (may contain owner nickname). Hardware serial numbers or IMEIs are **never** collected.
- **Retention Considerations:** Active until `DECOMMISSIONED` or deleted by user.

---

### 2.4 `DeviceCredential`
- **Purpose:** Stores the public key and enrollment token state for Plane 2 (Device Authentication).
- **Important Fields:**
  - `id` (UUID, PK)
  - `deviceId` (UUID, FK $\rightarrow$ `Device.id`, `ON DELETE CASCADE`)
  - `keyAlgorithm` (`ED25519` | `ECDSA_P256`)
  - `publicKeyPem` (Text — SPKI PEM public key)
  - `publicKeyFingerprint` (String, Unique — `SHA-256` hex digest)
  - `hardwareBacked` (Boolean — whether backed by Windows TPM 2.0 or Android Keystore)
  - `enrollmentTokenHash` (String, Nullable — `SHA-256` of one-time pairing token during `ENROLLMENT_PENDING`)
  - `enrollmentExpiresAt` (Timestamp UTC, Nullable)
  - `active` (Boolean)
  - `createdAt`, `confirmedAt`, `revokedAt` (Timestamp UTC)
- **Relationships:** Belongs to `Device`.
- **Sensitive Fields:** `enrollmentTokenHash` (cleared once confirmed). Device private keys **never** exist in the database.
- **Retention Considerations:** Retained alongside `Device` to verify historical event signatures; permanently invalidated upon revocation.

---

### 2.5 `DeviceSession`
- **Purpose:** Tracks active, short-lived authenticated user console sessions and device WebSocket/session bindings (formerly conceptual `Session` in Prompt 0001, expanded as `DeviceSession` to cover both Web Console sessions and authenticated real-time channels).
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `deviceId` (UUID, Nullable FK $\rightarrow$ `Device.id` — populated for agent realtime channels, `null` for Web Console browser sessions)
  - `sessionType` (`WEB_CONSOLE` | `DEVICE_STREAM`)
  - `tokenHash` (String, Unique — `SHA-256` hash of opaque session token)
  - `mfaVerifiedAt`, `stepUpVerifiedUntil` (Timestamp UTC, Nullable)
  - `ipAddressTruncated` (String — privacy-minimized IP or hash)
  - `userAgentSummary` (String)
  - `createdAt`, `lastActiveAt`, `expiresAt`, `revokedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User` and optionally `Device`.
- **Sensitive Fields:** `tokenHash` (raw session token is never stored).
- **Retention Considerations:** Expired or revoked rows purged automatically after **7 days** via background cleanup job.

---

### 2.6 `SecurityEvent`
- **Purpose:** Immutable chronological telemetry record matching `docs/product/event-taxonomy.md`.
- **Important Fields:**
  - `id` (UUID/ULID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `deviceId` (UUID, Nullable FK $\rightarrow$ `Device.id`, `ON DELETE SET NULL`)
  - `category` (`AUTHENTICATION` | `DEVICE` | `SECURITY` | `RECOVERY` | `THREATCHECK`)
  - `eventType` (String — canonical taxonomy enum)
  - `severity` (`INFO` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `source` (`WINDOWS_AGENT` | `ANDROID_AGENT` | `WEB_CONSOLE` | `BACKEND_WATCHDOG` | `THREATCHECK_ENGINE`)
  - `summary` (String)
  - `metadataJson` (JSONB — sanitized via `sanitizeLogMetadata()`, max 4 KB)
  - `signatureVerified` (Boolean)
  - `riskScoreDelta` (Int), `riskScoreAfter` (Int)
  - `occurredAt`, `ingestedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User` and `Device`; referenced by `Alert` and `RiskAssessment`.
- **Sensitive Fields:** `metadataJson` (strictly sanitized; never contains passwords, keys, or raw URL secrets).
- **Retention Considerations:** Default **90 days** rolling retention (user-configurable 7–365 days).

---

### 2.7 `Alert`
- **Purpose:** Prioritized, deduplicated security notification requiring user visibility or acknowledgement.
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `deviceId` (UUID, Nullable FK $\rightarrow$ `Device.id`)
  - `sourceEventId` (UUID, Nullable FK $\rightarrow$ `SecurityEvent.id`)
  - `category` (`SECURITY` | `DEVICE` | `LOCATION` | `TAMPER` | `THREAT` | `RECOVERY` | `SYSTEM`)
  - `severity` (`INFO` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `dedupKey` (String, Indexed)
  - `occurrenceCount` (Int, Default `1`)
  - `title` (String), `description` (String)
  - `status` (`OPEN` | `ACKNOWLEDGED` | `RESOLVED`)
  - `createdAt`, `lastSeenAt`, `acknowledgedAt`, `resolvedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User`, `Device`, and optional triggering `SecurityEvent`.
- **Sensitive Fields:** None beyond device context.
- **Retention Considerations:** Resolved alerts retained for **90 days** (or purged on user request).

---

### 2.8 `LocationRecord`
- **Purpose:** Stores permission-aware, encrypted location snapshots for VAJRA Locate and Lost Mode recovery.
- **Important Fields:**
  - `id` (UUID, PK)
  - `deviceId` (UUID, FK $\rightarrow$ `Device.id`, `ON DELETE CASCADE`)
  - `encryptedCoordinates` (Bytes — AES-256-GCM ciphertext of `{ latitude, longitude }` bound with AAD `userId:deviceId`)
  - `locationSource` (`ANDROID_FUSED_GPS` | `ANDROID_NETWORK` | `WINDOWS_LOCATION_API` | `IP_APPROXIMATE`)
  - `accuracyTier` (`PRECISE` | `MODERATE` | `COARSE` | `APPROXIMATE_IP`)
  - `accuracyMeters` (Float)
  - `permissionState` (`GRANTED_BACKGROUND` | `GRANTED_FOREGROUND_ONLY` | `DENIED` | `OS_DISABLED`)
  - `batteryPct` (Int, Nullable)
  - `capturedAt`, `receivedAt`, `expiresAt` (Timestamp UTC)
- **Relationships:** Belongs to `Device`.
- **Sensitive Fields:** `encryptedCoordinates` (High-sensitivity physical location PII — encrypted at the application layer before SQL write).
- **Retention Considerations:** Strict short retention: only the latest **10 records** per device or records younger than **7 days** (whichever is smaller) are kept unless Lost Mode is actively enabled; purged immediately when user disables location or revokes device.

---

### 2.9 `RemoteCommand`
- **Purpose:** Represents an allowlisted, step-up authorized instruction in Plane 3 (Command Authorization).
- **Important Fields:**
  - `id` (UUID, PK)
  - `targetDeviceId` (UUID, FK $\rightarrow$ `Device.id`, `ON DELETE CASCADE`)
  - `requesterUserId` (UUID, FK $\rightarrow$ `User.id`)
  - `commandType` (`REQUEST_DEVICE_STATUS` | `REQUEST_LOCATION` | `RING_PHONE` | `ENABLE_LOST_MODE` | `DISABLE_LOST_MODE` | `DISPLAY_RECOVERY_MESSAGE`)
  - `parametersJson` (JSONB — strictly schema-validated)
  - `status` (`PENDING` | `AUTHORIZED` | `DISPATCHED` | `COMPLETED` | `FAILED` | `EXPIRED` | `REJECTED`)
  - `nonce` (String, Unique — 128-bit cryptographic nonce)
  - `serverSignature` (Text — detached signature from Backend Command Authority)
  - `stepUpMethod` (String), `auditLogId` (UUID)
  - `issuedAt`, `expiresAt`, `dispatchedAt` (Timestamp UTC)
- **Relationships:** Belongs to `Device` and `User`; `1:1` with `CommandResult`.
- **Sensitive Fields:** `parametersJson` (may contain recovery message text).
- **Retention Considerations:** Retained for **90 days** for security auditability.

---

### 2.10 `CommandResult`
- **Purpose:** Stores the cryptographically signed execution receipt returned by the target device for a `RemoteCommand`.
- **Important Fields:**
  - `id` (UUID, PK)
  - `commandId` (UUID, Unique FK $\rightarrow$ `RemoteCommand.id`, `ON DELETE CASCADE`)
  - `deviceId` (UUID, FK $\rightarrow$ `Device.id`)
  - `executionStatus` (`COMPLETED` | `COMPLETED_WITH_OS_AUDIO_RESTRICTION` | `PARTIAL_SUCCESS_NOTIFICATION_ONLY` | `OS_PERMISSION_DENIED` | `REJECTED_EXPIRED` | `REJECTED_INVALID_SIGNATURE` | `FAILED`)
  - `statusMessage` (String)
  - `resultMetadataJson` (JSONB)
  - `deviceSignature` (Text — signed by device private key)
  - `signatureVerified` (Boolean)
  - `executedAt`, `receivedAt` (Timestamp UTC)
- **Relationships:** Belongs to `RemoteCommand` and `Device`.
- **Sensitive Fields:** None.
- **Retention Considerations:** Retained alongside `RemoteCommand` (90 days).

---

### 2.11 `ThreatCheck`
- **Purpose:** Records a URL threat analysis request and its overall verdict.
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `redactedUrl` (Text — query secrets replaced with `[REDACTED]`)
  - `urlSha256Hash` (String, Indexed)
  - `normalizedHostname` (String, Indexed)
  - `analysisMode` (`STANDARD_PASSIVE` | `AUTHORIZED_HEADER_AUDIT`)
  - `riskScore` (Int, `0–100`)
  - `riskLevel` (`SAFE` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL` | `UNKNOWN`)
  - `verdictStatement` (String — never claims "100% safe")
  - `recommendation` (String)
  - `providerResultsJson` (JSONB — array of `ThreatIntelVerdict`)
  - `checkedAt` (Timestamp UTC)
- **Relationships:** Belongs to `User`; `1:N` with `ThreatIndicator`.
- **Sensitive Fields:** `redactedUrl` (raw unredacted URL is never persisted to disk).
- **Retention Considerations:** Retained for **30 days** by default; user can clear history at any time.

---

### 2.12 `ThreatIndicator`
- **Purpose:** Stores individual structural, lexical, domain, or provider evidence items attached to a `ThreatCheck` record.
- **Important Fields:**
  - `id` (UUID, PK)
  - `threatCheckId` (UUID, FK $\rightarrow$ `ThreatCheck.id`, `ON DELETE CASCADE`)
  - `indicatorCode` (String, e.g., `PUNYCODE_HOMOGRAPH_DETECTED`, `IP_LITERAL_HOSTNAME`, `URL_SHORTENER_DETECTED`, `PROVIDER_PHISHING_MATCH`)
  - `severity` (`INFO` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `scoreContribution` (Int)
  - `title` (String)
  - `evidenceSummary` (String)
- **Relationships:** Belongs to `ThreatCheck`.
- **Sensitive Fields:** `evidenceSummary` (must reference redacted URL only).
- **Retention Considerations:** Cascades on delete with `ThreatCheck` (30 days).

---

### 2.13 `RiskAssessment`
- **Purpose:** Stores explainable, deterministic risk calculation snapshots for a device over time (`docs/product/risk-engine.md`).
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `deviceId` (UUID, FK $\rightarrow$ `Device.id`, `ON DELETE CASCADE`)
  - `riskScore` (Int, `0–100`)
  - `securityScoreEquivalent` (Int, `0–100` where $100 - \text{riskScore}$)
  - `riskLevel` (`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `reasonsJson` (JSONB — structured array of `{ ruleId, points, label, detail, sourceEventId }`)
  - `recommendedAction` (String)
  - `calculatedAt` (Timestamp UTC)
- **Relationships:** Belongs to `Device` and `User`.
- **Sensitive Fields:** None.
- **Retention Considerations:** Retained for **90 days** to power posture trend visualizations.

---

### 2.14 `AuditLog`
- **Purpose:** Tamper-evident, append-only record of all security-sensitive actions across Plane 1, Plane 2, and Plane 3.
- **Important Fields:**
  - `id` (UUID, PK)
  - `sequenceNumber` (BigInt, Auto-incrementing per user or global chain)
  - `userId` (UUID, Nullable FK $\rightarrow$ `User.id`, `ON DELETE SET NULL`)
  - `actorDeviceId` (UUID, Nullable FK $\rightarrow$ `Device.id`, `ON DELETE SET NULL`)
  - `actorType` (`USER` | `DEVICE` | `SYSTEM_WATCHDOG`)
  - `action` (String, e.g., `USER_LOGIN`, `PASSKEY_REGISTERED`, `DEVICE_ENROLLED`, `DEVICE_REVOKED`, `COMMAND_AUTHORIZED`, `LOST_MODE_ENABLED`, `AUTHORIZED_AUDIT_ATTESTED`)
  - `targetResourceType` (String), `targetResourceId` (String)
  - `contextJson` (JSONB — sanitized via `sanitizeLogMetadata()`)
  - `previousEntryHash` (String — `SHA-256` hash of preceding audit record)
  - `entryHash` (String, Unique — `SHA-256(previousEntryHash || sequenceNumber || action || targetResourceId || canonicalJson(contextJson) || createdAt)`)
  - `createdAt` (Timestamp UTC)
- **Relationships:** References `User` and `Device`.
- **Sensitive Fields:** `contextJson` (redacted).
- **Retention Considerations:** Retained for **365 days** to preserve forensic audit integrity.

---

### 2.15 `RecoveryProfile`
- **Purpose:** Stores the user-configured contact template displayed on the Android Custom Recovery Screen during Lost Mode (`Module 4`).
- **Important Fields:**
  - `id` (UUID, PK)
  - `userId` (UUID, Unique FK $\rightarrow$ `User.id`, `ON DELETE CASCADE`)
  - `ownerDisplayAlias` (String, e.g., `"Ayush S."` — 1–48 chars)
  - `recoveryContactPhone` (String, Nullable — alternate contact number)
  - `recoveryContactEmail` (String, Nullable — alternate contact email)
  - `defaultRecoveryMessage` (String, Max 200 chars, e.g., `"This device is lost. Please contact the owner to arrange return."`)
  - `updatedAt` (Timestamp UTC)
- **Relationships:** `1:1` with `User`.
- **Sensitive Fields:** `recoveryContactPhone`, `recoveryContactEmail` (explicitly provided by the user for lockscreen display when Lost Mode is triggered).
- **Retention Considerations:** Retained while account is active; user can edit or clear at any time.
