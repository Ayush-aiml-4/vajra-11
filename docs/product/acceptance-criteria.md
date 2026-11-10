# VAJRA — Measurable Product & Security Acceptance Criteria

**Document Status:** Engineering Verification Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/product/PRD.md`, `docs/product/roadmap.md`, `docs/security/testing-strategy.md`

---

## 1. Device Enrollment Acceptance Criteria

A device must **never** transition to `TRUSTED` or `ACTIVE` unless all four conditions below are simultaneously satisfied and verified by automated tests:

```text
  Authenticated User Session (Plane 1 + Step-Up Verified)
+ Valid, Unexpired, Single-Use Enrollment Token (TTL <= 10 minutes)
+ Device Public Key Registered with Valid Proof-of-Possession Signature
+ Explicit User Confirmation of Device Identity in Web Console
────────────────────────────────────────────────────────────────────────
= Device Lifecycle State Transitions: ENROLLMENT_PENDING -> TRUSTED
```

### Measurable Verification Conditions
1. **Unauthenticated Rejection:** Submitting an enrollment request without a valid user session or valid enrollment token returns `401 Unauthorized`.
2. **Expired Token Rejection:** Submitting a device public key with an enrollment token older than `600 seconds` returns `410 Gone` (`ENROLLMENT_TOKEN_EXPIRED`).
3. **Replay / Reuse Rejection:** Reusing an already-consumed enrollment token a second time returns `409 Conflict` (`ENROLLMENT_TOKEN_ALREADY_USED`).
4. **Invalid Proof-of-Possession Rejection:** Submitting a `publicKeyPem` whose accompanying signature over the enrollment transcript fails verification returns `400 Bad Request` (`INVALID_KEY_PROOF`).
5. **Private Key Non-Transmission:** The enrollment request schema strictly rejects any payload containing private key fields (`privateKey`, `d`, `pkcs8`, `seed`).
6. **Unconfirmed Device Restriction:** While a device is in `ENROLLMENT_PENDING` (before the human owner clicks Confirm), any attempt by the device to submit operational `SecurityEvent` records or poll `RemoteCommand` queues is rejected with `403 Forbidden`.

---

## 2. Remote Command Acceptance Criteria

A remote command (`REQUEST_DEVICE_STATUS`, `REQUEST_LOCATION`, `RING_PHONE`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`) is accepted for dispatch and execution **only** if all six conditions below hold:

```text
  Authenticated User Session (with Fresh Step-Up Auth for Sensitive Commands)
+ Authorized Action (Strictly Allowlisted Enum — Never Shell/Code Execution)
+ Trusted Target Device Owned by Requester (Not REVOKED or COMPROMISED)
+ Valid, Unique 128-Bit Cryptographic Nonce (Not Previously Seen)
+ Not Expired (issuedAt <= now() <= expiresAt)
+ Immutable AuditLog Record Created BEFORE Dispatch
────────────────────────────────────────────────────────────────────────
= Command Authorized, Signed by Backend, & Executed by Endpoint Agent
```

### Measurable Verification Conditions
1. **Allowlist Enforcement:** Calling `POST /api/devices/:id/commands` with `EXECUTE_SHELL`, `EXECUTE_COMMAND`, `REMOTE_TERMINAL`, `UPLOAD_EXECUTABLE`, or `DOWNLOAD_AND_EXECUTE` is immediately rejected with `400 Bad Request (PROHIBITED_CAPABILITY)`.
2. **Step-Up Auth Gate:** Calling `RING_PHONE`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`, or `REQUEST_LOCATION` without a step-up verification timestamp within the last 5 minutes returns `403 Forbidden (STEP_UP_AUTH_REQUIRED)`.
3. **Cross-Tenant Isolation:** Attempting to issue a command to a `deviceId` owned by another user returns `404 Not Found`.
4. **Revoked / Compromised Target Rejection:** Attempting to issue a command to a device in `REVOKED` or `COMPROMISED` state returns `409 Conflict (INVALID_DEVICE_LIFECYCLE_STATE)`.
5. **Replay Rejection on Agent & Server:** Re-submitting a command envelope with a duplicate `nonce` or `commandId` is rejected and logged as a replay anomaly.
6. **Expiration Enforcement:** Any command where `currentUtcTime > expiresAt` transitions to `EXPIRED` and is never executed by the endpoint agent even if delivered late after an offline period.
7. **Pre-Dispatch Audit Guarantee:** If the `AuditLog` database write fails, the transaction rolls back and the command is **never** dispatched.

---

## 3. ThreatCheck Acceptance Criteria

### Measurable Verification Conditions
1. **Zero "100% Safe" Claims (Epistemic Honesty):**
   - No API response, UI component, or AI explanation in ThreatCheck may ever output the phrase `"100% safe"` or `"guaranteed safe"`.
   - Clean checks must return bounded language such as: *"No known threat indicators were detected by the available checks."*
2. **Mandatory Query Secret Redaction:**
   - Submitting `https://example.com/reset?token=SECRET123&key=MYKEY` must persist and log **only** `https://example.com/reset?token=[REDACTED]&key=[REDACTED]`. Raw secret values must never appear in `ThreatCheck`, `ThreatIndicator`, `AuditLog`, or stdout logs.
3. **SSRF Protection:**
   - Submitting URLs targeting `127.0.0.1`, `localhost`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or `169.254.169.254` must be blocked locally prior to any network lookup (`400 SSRF_BLOCKED_TARGET`).
4. **Vendor-Neutral Provider Abstraction:**
   - ThreatCheck must execute cleanly using the built-in `LocalHeuristicProvider` even when zero third-party API keys (`VirusTotal`, `Google Safe Browsing`, `URLhaus`) are configured.
5. **No Unauthorized Active Scanning:**
   - Standard URL Check performs zero port scans, directory brute-forcing, or exploit probes against the submitted hostname.

---

## 4. VAJRA Locate & Recovery Acceptance Criteria

### Measurable Verification Conditions
1. **Explicit Four-Tuple Location Metadata:**
   - Every location response (`GET /api/devices/:id/location`) must include `locationSource`, `accuracyTier` / `accuracyMeters`, `capturedAt` (`Timestamp`), and `permissionState`.
2. **Zero IP-as-GPS Misrepresentation:**
   - When `locationSource === 'IP_APPROXIMATE'`, `isApproximateIpOnly` must be `true`, `accuracyTier` must be `'APPROXIMATE_IP'`, and the UI must display an explicit coarse-location warning rather than a pinpoint GPS marker.
3. **Application-Layer Coordinate Encryption:**
   - Raw `latitude` and `longitude` floats must be encrypted with AES-256-GCM prior to storage in `LocationRecord.encryptedCoordinates`.
4. **Custom Recovery Screen Privacy & OS Respect:**
   - The Android Custom Recovery Screen displays only `Owner Name`, `Recovery Contact`, and `Masked Device ID` (last 4 characters).
   - Local deactivation of Lost Mode on the phone requires the owner to unlock the Android OS Keyguard first.

---

## 5. Risk Engine & Security Timeline Acceptance Criteria

### Measurable Verification Conditions
1. **Explainable Score Breakdown:**
   - Every `RiskAssessment` (`riskScore: 0–100`) must include a non-empty `reasons[]` array whenever `riskScore > 0`, where the sum of `reasons[].points` (clamped to `100`) equals `riskScore`, paired with a clear `recommendedAction`.
2. **Alert Deduplication:**
   - Multiple identical security events for the same `(userId, deviceId, alertCategory, ruleId)` within the active cooldown window increment `occurrenceCount` on the existing open alert rather than creating duplicate alert rows.
3. **Log & Timeline Sanitization:**
   - All `SecurityEvent.metadataJson` and `AuditLog.contextJson` objects pass through `sanitizeLogMetadata()`, ensuring zero passwords, tokens, cookies, or private keys are stored.
