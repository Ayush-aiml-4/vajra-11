# VAJRA — Security & Platform Testing Strategy

**Document Status:** Quality & Security Assurance Specification (`IMPLEMENTED` in `tests/foundation.test.ts` & `tests/auth-foundation.test.ts`: Health, Shared Types, Argon2id, TOTP + AES-256-GCM, Single-Use Recovery Codes, Sessions, Auth API, CSRF/Authorization, Audit Chain Tamper Detection & Secret Hygiene; Platform/ThreatCheck suites `PLANNED`)  
**Test Runner:** Node.js native test runner via `tsx --test` (`npm test`)

---

## 1. Testing Philosophy & Verification Gate

Every milestone in VAJRA must pass automated verification (`npm run lint`, `npm run typecheck`, `npm test`, `npm run build`) before completion. Security controls (such as signature verification, command allowlisting, replay protection, and secret redaction) must be verified by **negative security tests** that explicitly attempt to violate each boundary and assert that the system rejects the attempt.

---

## 2. Five Core Testing Categories

### Category 1 — Unit Tests (`IMPLEMENTED` Foundation + `PLANNED` Expansion)
Fast, isolated deterministic tests requiring no external network or database:
1. **Security Utilities (`@vajra/security` — `IMPLEMENTED`):**
   - Verify every item in `PROHIBITED_CAPABILITIES` (`stealth_spyware`, `keylogging`, `arbitrary_remote_shell_execution`, etc.) returns `false` from `isCapabilityPermitted()`.
   - Verify `sanitizeLogMetadata()` redacts `password`, `secret`, `token`, `key`, `authorization`, `cookie`, and `credential` fields and truncates oversized strings.
   - Verify `redactUrlSecrets()` strips sensitive query parameters (`?token=SECRET` $\rightarrow$ `?token=[REDACTED]`).
2. **Runtime Configuration (`@vajra/config` — `IMPLEMENTED`):**
   - Verify valid and invalid `NODE_ENV`, `PORT`, and `SESSION_TTL_SECONDS` inputs without leaking environment secrets.
3. **Explainable Risk Engine (`PLANNED` — Prompt 0010):**
   - Feed deterministic combinations of `SecurityEvent` and `DeviceState` fixtures into the pure risk calculation function and assert that `riskScore` (`0–100`), `riskLevel`, `reasons[]`, and `recommendedAction` match exact expected outputs.
4. **Event Taxonomy & Schema Validators (`PLANNED` — Prompt 0007):**
   - Verify valid canonical events pass and unknown `eventType` or oversized (> 4 KB) metadata payloads are rejected.

---

### Category 2 — Integration Tests (`IMPLEMENTED` `/api/health` + `PLANNED` DB/API)
Tests exercising the Express HTTP pipeline, middleware, and persistence layer:
1. **Health Endpoint (`tests/foundation.test.ts` — `IMPLEMENTED`):**
   - Verify `GET /api/health` returns `200 OK`, `{"status":"ok","service":"vajra-api"}`, sets `X-Content-Type-Options: nosniff`, and leaks no extra keys.
2. **Database & Audit Chain Integrity (`PLANNED` — Prompt 0003):**
   - Verify `AuditLog` hash chaining (`previousEntryHash -> entryHash`) detects any simulated tampering or out-of-order modification of historical rows.
3. **Device Lifecycle & Enrollment Ceremony (`PLANNED` — Prompt 0004):**
   - Test full enrollment flow: generate token $\rightarrow$ submit ephemeral Ed25519/ECDSA public key with valid Proof-of-Possession signature $\rightarrow$ user confirms $\rightarrow$ device transitions `ENROLLMENT_PENDING -> TRUSTED -> ACTIVE`.
4. **Alert Deduplication & Resolution (`PLANNED` — Prompt 0007):**
   - Submit 5 identical `LOGIN_FAILURE` events within the cooldown window and assert that only 1 `OPEN` alert is created with `occurrenceCount = 5`.

---

### Category 3 — Negative Security & Adversarial Tests (`PLANNED` — Prompts 0003–0011)
Dedicated test suites verifying that every threat in `docs/security/threat-model.md` is blocked:
1. **Authentication & Session Security:**
   - Reject expired, revoked, or tampered `__Host-vajra_session` cookies (`401 Unauthorized`).
   - Enforce brute-force lockout (`423 Locked` / `429 Too Many Requests`) after 5 failed login attempts.
2. **Three-Plane Authorization Separation:**
   - Assert that User A cannot read, locate, ring, or revoke User B's devices (`404 Not Found` / `403 Forbidden`).
   - Assert that a valid Plane 2 Device Signature cannot call Plane 1 Web Console endpoints (`GET /api/devices`, `POST /api/devices/:id/commands`).
   - Assert that a standard Plane 1 User Session **without** fresh Step-Up Auth (`stepUpVerifiedUntil`) is rejected (`403 STEP_UP_AUTH_REQUIRED`) when calling `RING_PHONE`, `ENABLE_LOST_MODE`, or `GET /api/devices/:id/location`.
3. **Replay Attack Protection:**
   - Capture a valid signed `RemoteCommand` or device heartbeat and submit it a second time with the same `nonce`; assert immediate rejection (`409 Conflict / REJECTED_REPLAY`).
4. **Invalid Signatures & Key Compromise:**
   - Sign a device heartbeat or `CommandResult` with an unregistered or `REVOKED` keypair and assert `401/403` rejection and `AuditLog` anomaly recording.
5. **Expired Commands:**
   - Construct a signed `RemoteCommand` with `expiresAt = now() - 10s` and assert that both the backend dispatcher and agent command verifier reject it (`REJECTED_EXPIRED`).
6. **Prohibited Remote Command Rejection:**
   - Attempt to `POST /api/devices/:id/commands` with `commandType: "EXECUTE_SHELL"` or `"DOWNLOAD_AND_EXECUTE"`; assert `400 Bad Request (PROHIBITED_CAPABILITY)`.

---

### Category 4 — Platform & Resilience Tests (`PLANNED` — Prompts 0005, 0006, 0008)
Tests validating Windows Agent, Android App, and offline recovery state machines:
1. **Windows Agent Telemetry & ACLs:**
   - Verify parsing of simulated Windows Event IDs (`4624`, `4625`, `4800`, `4801`, `5001`) into canonical `SecurityEvent` objects with zero credential leakage.
2. **Android Permission Degradation:**
   - Simulate `PermissionState = DENIED` and `GRANTED_FOREGROUND_ONLY` during a remote `REQUEST_LOCATION` command and verify graceful `OS_PERMISSION_DENIED` receipt generation.
   - Simulate Android 14+ `USE_FULL_SCREEN_INTENT` denial during `ENABLE_LOST_MODE` and verify fallback to lockscreen notification (`PARTIAL_SUCCESS_NOTIFICATION_ONLY`).
3. **Network Failure & Offline Recovery:**
   - Simulate endpoint offline state $\rightarrow$ Backend Watchdog transitions device to `OFFLINE` $\rightarrow$ queue `ENABLE_LOST_MODE` $\rightarrow$ reconnect device with signed heartbeat $\rightarrow$ verify queued command delivery and `ACTIVE`/`LOST` state restoration.

---

### Category 5 — ThreatCheck Test Matrix (`PLANNED` — Prompt 0009)
Comprehensive fixture suite testing URL analysis accuracy, safety, and privacy:
1. **Malicious & Phishing URL Fixtures:** Brand-spoofing subdomains (`https://paypal.com.login-verify.example.xyz/auth`).
2. **Redirect & Open-Redirect Cases:** URLs embedding external redirect targets (`https://trusted.example.com/redirect?next=http://evil.example.org`).
3. **Punycode / IDN Homograph Cases:** Mixed-script and `xn--` domains (`https://xn--80ak6aa92e.com`).
4. **IP-Literal & Obfuscated Hostname Cases:** Raw IPv4 (`http://198.51.100.10:8080/login`), IPv6, and userinfo `@` tricks.
5. **URL Shortener Cases:** Known shortener domains (`https://bit.ly/3xYzAbC`) flagged with destination-masking advisories.
6. **Malformed & SSRF-Attempt URLs:**
   - Reject `javascript:alert(1)`, `file:///etc/passwd`, `http://127.0.0.1:3000/api/health`, `http://169.254.169.254/latest/meta-data/`, and RFC 1918 private IPs (`10.0.0.1`, `192.168.1.1`) with `SSRF_BLOCKED_TARGET`.
7. **Sensitive Query Parameter Redaction:**
   - Verify `https://example.com/reset?token=SECRET123&session_key=ABC` is transformed into `https://example.com/reset?token=[REDACTED]&session_key=[REDACTED]` prior to persistence, logging, or provider lookup.
8. **Epistemic Honesty Assertion:**
   - Assert that no ThreatCheck response string ever matches `/100%\s*safe/i`.
