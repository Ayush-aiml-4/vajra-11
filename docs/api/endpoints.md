# VAJRA — Source-Grounded REST API Endpoint Specification (Prompt 0051)

**Base URL Prefix:** `/api`  
**Document Status:** Synchronized directly with Express route definitions in `src/server/app.ts`, `src/server/auth/routes.ts`, `src/server/devices/routes.ts`, and `src/server/notifications/routes.ts`.  
**Related Documents:** `docs/security/authentication.md`, `docs/security/csrf.md`, `docs/security/authorization-matrix.md`, `docs/security/remote-command-security.md`, `docs/security/device-enrollment.md`, `docs/security/production-checklist.md`

---

## Global API Conventions

- **Content-Type:** `application/json; charset=utf-8` (request bodies capped at `16 KB` via `express.json({ limit: '16kb' })`).
- **Response Cache Policy:** All `/api/*` routes emit `Cache-Control: no-store`.
- **Standard Error Envelope:**
  ```json
  {
    "error": {
      "code": "STEP_UP_REQUIRED",
      "message": "MFA step-up verification is required for this sensitive operation."
    }
  }
  ```
- **Authentication Planes:**
  - **Plane 1 (Browser User Session):** `HttpOnly` cookie (`__Host-vajra_session` with `Secure; Path=/; SameSite=None; Partitioned` over HTTPS; `vajra_session` with `SameSite=Lax` over plain HTTP localhost) + `X-CSRF-Token` header and `Origin`/`Referer` check on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`). Client-supplied `X-Forwarded-*` headers are ignored unless `trust proxy` is enabled or the peer socket + `Host` header belong to a verified local loopback proxy.
  - **Plane 2 (Cryptographic Device Auth):** `X-Vajra-Device-Id`, `X-Vajra-Timestamp` (±120s window), `X-Vajra-Nonce` (atomic replay table), and `X-Vajra-Signature` (`VAJRA-DEVICE-AUTH-V1` ECDSA P-256 signature over method + path + timestamp + nonce + SHA-256 body hash).
  - **Plane 3 (Step-Up Command Grant):** Active Plane 1 session verified via `POST /api/auth/step-up` with a 5-minute, single-use, action-scoped grant (`DEVICE_REVOKE`, `DEVICE_COMPROMISED`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `SENSITIVE_COMMAND`).
- **Cross-User Isolation:** Any reference to a device, session, notification, or command owned by another user returns `404` (`DEVICE_NOT_FOUND` / `SESSION_NOT_FOUND` / `NOTIFICATION_NOT_FOUND` / `COMMAND_NOT_FOUND`) to prevent enumeration.

---

## 0. Health & Readiness (`src/server/app.ts` — `IMPLEMENTED`)

| Method & Path | Auth | Purpose & Response |
| :--- | :--- | :--- |
| `GET /api/health` | Public | Liveness probe -> `200 { "status": "ok", "service": "vajra-api" }`. Never exposes secrets or environment variables. |
| `GET /api/ready` | Public | Readiness probe against `IdentityRepository` (bounded timeout) -> `200 { "status": "ready", "checks": { "identityStore": { "ok": true } } }` or `503 { "status": "not_ready" }` without connection strings. |

---

## 1. Authentication, MFA, Step-Up & Sessions (`src/server/auth/routes.ts` — `IMPLEMENTED`)

> **Note on WebAuthn Passkeys:** While `PasskeyCredential` exists in `prisma/schema.prisma`, runtime WebAuthn assertion routes are `NOT IMPLEMENTED`. Authentication uses Argon2id passwords, AES-256-GCM encrypted RFC 6238 TOTP MFA, and SHA-256 hashed single-use recovery codes.

| Method & Path | Auth | Request Body | Behavior & Status Codes |
| :--- | :--- | :--- | :--- |
| `POST /api/auth/register` | Public | `{ "email", "password", "displayName" }` | Validates password policy, hashes with Argon2id, creates `User` + initial session cookie, returns `{ user, csrfToken, sessionExpiresAt }` (`201`). Returns `409 EMAIL_ALREADY_REGISTERED` on duplicate email. |
| `POST /api/auth/login` | Public | `{ "email", "password", "totpCode"?, "recoveryCode"? }` | Verifies Argon2id password, enforces account lockout (`423 ACCOUNT_LOCKED`) & IP+email rate limit (`429 RATE_LIMITED`; `X-Forwarded-For` ignored unless trusted proxy). If MFA enabled, requires `totpCode` or single-use `recoveryCode` (`401 MFA_REQUIRED`). Recovery-code login revokes all other sessions. Sets session cookie and returns `{ user, csrfToken, sessionExpiresAt }` (`200`). |
| `POST /api/auth/logout` | Plane 1 + CSRF | `{ "revokeAllSessions"?: boolean }` | Revokes current session (or all user sessions), clears cookies, writes `USER_LOGOUT` audit entry (`200`). |
| `GET /api/auth/me` | Plane 1 | — | Restores current user profile, MFA state, `csrfToken`, and active step-up metadata (`200`), or `401 UNAUTHENTICATED`. |
| `GET /api/auth/sessions` | Plane 1 | — | Lists active non-revoked browser sessions (`id`, `createdAt`, `lastSeenAt`, `expiresAt`, `ipAddress`, `userAgent`, `stepUpActive`, `isCurrent`) without token hashes (`200`). |
| `POST /api/auth/sessions/:sessionId/revoke` | Plane 1 + CSRF | — | Revokes an owned session (`200`), clearing cookies if revoking current session; `404 SESSION_NOT_FOUND` for unknown/foreign IDs. |
| `POST /api/auth/mfa/setup/initiate` | Plane 1 + CSRF | `{ "currentPassword" }` | Verifies current password, generates encrypted pending TOTP secret + `otpauth://` URI (`200`). |
| `POST /api/auth/mfa/setup/confirm` | Plane 1 + CSRF | `{ "totpCode" }` | Verifies TOTP code, enables MFA on account, generates and returns **8 single-use recovery codes once** (stored hashed at rest) (`200`). |
| `POST /api/auth/mfa/disable` | Plane 1 + CSRF | `{ "currentPassword", "totpCode"?, "recoveryCode"? }` | Verifies password + MFA proof, disables TOTP MFA, clears recovery codes, and revokes all other sessions (`200`). |
| `POST /api/auth/mfa/recovery-codes/regenerate` | Plane 1 + CSRF | `{ "currentPassword", "totpCode" }` | Verifies password + live TOTP code, replaces recovery codes with 8 fresh single-use codes, and revokes all other sessions (`200`). |
| `POST /api/auth/step-up` | Plane 1 + CSRF | `{ "totpCode", "actionScope" }` | Verifies TOTP for MFA-enabled accounts and binds a 5-minute single-use `actionScope` (`DEVICE_REVOKE`, `DEVICE_COMPROMISED`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `SENSITIVE_COMMAND`) to the session (`200`). |
| `POST /api/auth/password/change` | Plane 1 + CSRF | `{ "currentPassword", "newPassword", "totpCode"?, "recoveryCode"? }` | Verifies current password (+ MFA if enabled), updates Argon2id hash, and revokes all other sessions (`200`). |
| `POST /api/auth/account/delete` | Plane 1 + CSRF | `{ "currentPassword", "confirmation": "DELETE MY VAJRA ACCOUNT", "totpCode"?, "recoveryCode"? }` | Verifies password (+ MFA if enabled), decommissions account, revokes sessions/devices, clears cookies (`200`). |

---

## 2. Audit Trail Verification (`src/server/app.ts`, `src/server/notifications/routes.ts` — `IMPLEMENTED`)

| Method & Path | Auth | Behavior & Response |
| :--- | :--- | :--- |
| `GET /api/audit` | Plane 1 | Returns user-scoped `AuditLog` entries and SHA-256 hash-chain integrity check (`{ entries, chainIntegrity }`). |
| `GET /api/audit/verify` | Plane 1 | Recomputes SHA-256 hash links across up to 500 user-scoped `AuditLog` entries (`{ verification: { valid, checkedCount, verifiedAt, headEntryHash } }`). |
| `POST /api/audit/verify` | Plane 1 + CSRF | Runs full SHA-256 chain verification and appends `AUDIT_CHAIN_VERIFIED` to `AuditLog` (`200`). |

---

## 3. Device Enrollment, Plane-2 Telemetry & Lifecycle (`src/server/devices/routes.ts` — `IMPLEMENTED`)

| Method & Path | Auth | Purpose & Behavior |
| :--- | :--- | :--- |
| `GET /api/devices` | Plane 1 | Lists devices owned by caller (excludes `DECOMMISSIONED` unless `?includeDecommissioned=true`). |
| `GET /api/devices/:id` | Plane 1 | Returns owned device details, active credential fingerprint, and latest risk fields (`404 DEVICE_NOT_FOUND` if missing/foreign). |
| `POST /api/devices/enrollment/initiate` | Plane 1 + CSRF | Creates `ENROLLMENT_PENDING` device + single-use SHA-256 hashed pairing token (10-minute TTL); returns raw `enrollmentToken` once (`201`). |
| `POST /api/devices/enrollment/submit` | Enrollment Token + PoP | Verifies single-use pairing token, platform match, ECDSA P-256 SPKI public key uniqueness (`409 DUPLICATE_PUBLIC_KEY` if reused), and Proof-of-Possession signature; stores `PENDING_CONFIRMATION` credential (`200`). |
| `POST /api/devices/:id/enrollment/confirm` | Plane 1 + CSRF (+ Step-Up if MFA enabled) | Activates `DeviceCredential`, transitions device to `TRUSTED`, records `DEVICE_ENROLLED` (`200`). |
| `POST /api/devices/:id/revoke` | Plane 1 + CSRF + Step-Up (`DEVICE_REVOKE`) | Transitions device to `REVOKED`, revokes active credentials, **cancels all pending `RemoteCommand`s**, consumes step-up grant (`200`). Re-enrollment requires a fresh keypair + new pairing token. |
| `POST /api/devices/:id/compromised` | Plane 1 + CSRF + Step-Up (`DEVICE_COMPROMISED`) | Flags device `COMPROMISED`, blocks Plane-2 authentication and remote commands, emits high-severity alert (`200`). |
| `POST /api/devices/:id/decommission` | Plane 1 + CSRF (+ Step-Up if MFA enabled) | Permanently transitions device to `DECOMMISSIONED`, revokes remaining credentials, and **cancels all pending `RemoteCommand`s** (`200`). |
| `POST /api/devices/auth/verify` | Plane 2 Device Signature | Verifies `VAJRA-DEVICE-AUTH-V1` signature, ±120s timestamp, and single-use nonce (`200` or `401`/`403`/`409`). |
| `POST /api/devices/credentials/rotate` | Plane 2 Device Signature | Rotates active device ECDSA P-256 public key using a signed proof from both current and new keys (`200`). |
| `POST /api/devices/:id/heartbeat` | Plane 2 Device Signature | Route-bound (`:id === X-Vajra-Device-Id`). Persists `DeviceHeartbeat`, updates `lastHeartbeatAt`, `lastSeenAt`, `connectivityStatus`, `osVersion`, `agentVersion`, transitions `TRUSTED`/`OFFLINE` -> `ACTIVE` when online, refreshes risk score, expires stale commands, and returns `pendingCommands` (`200`). |
| `GET /api/devices/:id/battery-history` | Plane 1 | Returns 24h battery & charging telemetry for owned `ANDROID` device (`400 UNSUPPORTED_PLATFORM` for `WINDOWS`). |

---

## 4. Security Events, Notifications, Risk, Remote Commands, ThreatCheck & Reports (`src/server/notifications/routes.ts` — `IMPLEMENTED`)

### 4.1 Notifications, Activity & Risk

| Method & Path | Auth | Behavior |
| :--- | :--- | :--- |
| `GET /api/notifications` | Plane 1 | Lists user-scoped alerts/notifications (`status`, `severity`, `category`, `unreadCount`). |
| `POST /api/notifications/:id/read` | Plane 1 + CSRF | Marks owned notification read (`200`). |
| `POST /api/notifications/read-all` | Plane 1 + CSRF | Marks all unread notifications read for caller (`200`). |
| `POST /api/notifications/:id/acknowledge` | Plane 1 + CSRF | Acknowledges owned alert and writes `NOTIFICATION_ACKNOWLEDGED` audit entry (`200`). |
| `POST /api/notifications/:id/dismiss` | Plane 1 + CSRF | Dismisses owned notification and writes `NOTIFICATION_DISMISSED` audit entry (`200`). |
| `GET /api/activity` | Plane 1 | Returns human-readable security activity feed mapped from `AuditLog` (`200`). |
| `POST /api/devices/:id/events` | Plane 2 Device Signature | Route-bound signed device security event ingestion (`201`). Sanitizes prohibited payload fields, computes deterministic risk score, and generates deduplicated alerts. |
| `POST /api/events/ingest` | Plane 1 + CSRF | Authenticated user/console security event ingestion for an owned eligible device (`201`). |
| `GET /api/events` | Plane 1 | Chronological user-scoped `SecurityEvent` query (`?deviceId=&category=&severity=&limit=`). |
| `GET /api/security/risk` | Plane 1 | Returns explainable `0–100` account & per-device risk posture (`200`). |

### 4.2 Remote Commands & Recovery Actions (`IMPLEMENTED` — Capability-Enforced & Receipt-Gated)

**Platform Capability Matrix (Enforced Server-Side in `validateActionCapabilityForDevice`):**

| Action / Command Type | Windows (`WINDOWS`) | Android (`ANDROID`) | Execution Semantics |
| :--- | :---: | :---: | :--- |
| `REQUEST_DEVICE_STATUS` | **Allowed** | **Allowed** | Queued as `RemoteCommand` (`QUEUED`); transitions to `COMPLETED`/`FAILED` **only** upon Plane-2 signed receipt. |
| `RING_DEVICE` | **Rejected (`400`)** | **Allowed** | Requires MFA step-up when MFA enabled; queued for Android visible foreground ring service; rejected on Windows (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`). |
| `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` | **Allowed via `/actions` only** | **Allowed via `/actions` only** | Requires MFA step-up when MFA enabled. Server-side VAJRA account lifecycle transition (`LOST` <-> `ACTIVE`/`TRUSTED`, `executionScope: "SERVER_ACCOUNT_STATE"`, `physicalLockApplied: false`, `liveLocationTracking: false`). Does **not** fabricate `ONLINE` connectivity or lock OS screens. Rejected on `/commands` (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`). |
| `REQUEST_LOCATION` | **Rejected (`400`)** | **Rejected (`400`)** | `NOT IMPLEMENTED` on native agents; rejected with `400 UNSUPPORTED_COMMAND_FOR_PLATFORM` before step-up consumption or DB writes. |
| `DISPLAY_RECOVERY_MESSAGE` | **Rejected (`400`)** | **Rejected (`400`)** | `NOT IMPLEMENTED` on native agents; rejected with `400 UNSUPPORTED_COMMAND_FOR_PLATFORM` before step-up consumption or DB writes. |
| Shell / Arbitrary Code | **Rejected (`400`)** | **Rejected (`400`)** | Prohibited by VAJRA security charter (`400 INVALID_ACTION_TYPE`). |

| Method & Path | Auth | Behavior |
| :--- | :--- | :--- |
| `GET /api/devices/:id/commands` | Plane 1 | Lists remote commands and receipts for an owned device (`200`). |
| `POST /api/devices/:id/commands` | Plane 1 + CSRF (+ Step-Up for sensitive) | Queues a supported device-executable command (`REQUEST_DEVICE_STATUS` on Windows/Android; `RING_DEVICE` on Android). Rejects `REVOKED`/`DECOMMISSIONED`/`COMPROMISED` devices (`409 DEVICE_NOT_ELIGIBLE`) and unsupported platform commands (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`). |
| `POST /api/devices/:id/actions` | Plane 1 + CSRF (+ Step-Up for sensitive) | Console recovery action endpoint supporting `REQUEST_DEVICE_STATUS`, Android `RING_DEVICE`, and server-side account `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`. |
| `GET /api/devices/:id/commands/pending` | Plane 2 Device Signature | Route-bound device poll returning non-expired `QUEUED`/`DELIVERED` commands and marking `QUEUED` -> `DELIVERED` (`200`). |
| `POST /api/devices/:id/commands/:commandId/acknowledge` | Plane 2 Device Signature | Route-bound signed device acknowledgement (`QUEUED`/`DELIVERED` -> `ACKNOWLEDGED`) (`200`). |
| `POST /api/devices/:id/commands/:commandId/result` | Plane 2 Device Signature | Route-bound signed terminal device receipt (`COMPLETED` or `FAILED`). Enforces terminal-state immutability (idempotent on identical status, `409 INVALID_COMMAND_STATE` on conflicting replay). |
| `POST /api/devices/:id/commands/:commandId/cancel` | Plane 1 + CSRF | Cancels an owned `QUEUED` or `DELIVERED` command (`200`), or returns `409 COMMAND_NOT_CANCELLABLE` if already `ACKNOWLEDGED`/`COMPLETED`/`FAILED`/`EXPIRED`/`CANCELLED`. |

### 4.3 ThreatCheck, Analytics, Exports & Non-Production Demo Routes

| Method & Path | Auth | Behavior |
| :--- | :--- | :--- |
| `POST /api/threatcheck/inspect` | Plane 1 + CSRF | Zero-outbound-fetch SSRF-safe URL lexical/destination inspection; redacts query/fragment secrets, persists `ThreatCheck` + `ThreatIndicator`s, returns explainable verdict + limitations statement (`200`). |
| `GET /api/threatcheck/history` | Plane 1 | Paginated user-scoped ThreatCheck history (`?limit=&offset=&verdict=&deviceId=`) (`200`). |
| `GET /api/analytics/summary` | Plane 1 | Persisted user-scoped posture summary (`dataSource: "PERSISTED"`) (`200`). |
| `GET /api/reports/export` | Plane 1 | Downloads user-scoped JSON (`?format=json`) or formula-injection-safe CSV (`?format=csv`) security report and logs `SECURITY_REPORT_EXPORTED` (`200`). |
| `POST /api/demo/event` & `POST /api/demo/seed` | Plane 1 + CSRF (Dev/Test Only) | Returns **`404 DEMO_DISABLED`** whenever `NODE_ENV=production`, `APP_ENV=production`, or `VAJRA_ENABLE_DEMO_ENDPOINTS=false`. |
