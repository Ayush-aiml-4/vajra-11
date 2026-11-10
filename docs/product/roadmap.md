# VAJRA — 12-Stage Engineering & Security Roadmap

**Document Status:** Master Development Roadmap (Prompt 0002 — Stages `0001` & `0002` Completed; Stages `0003`–`0012` `PLANNED`)  
**Related Documents:** `docs/product/PRD.md`, `docs/product/mvp.md`, `docs/product/acceptance-criteria.md`

---

## Stage Overview

```text
[0001] Foundation (COMPLETED)
   ↓
[0002] Product & Security Specification (COMPLETED — CURRENT STAGE)
   ↓
[0003] Database + Authentication Foundation
   ↓
[0004] Device Identity & Enrollment
   ↓
[0005] Windows Agent
   ↓
[0006] Android Application
   ↓
[0007] Event & Alert System
   ↓
[0008] Device Recovery
   ↓
[0009] ThreatCheck
   ↓
[0010] Risk Engine
   ↓
[0011] Security Hardening
   ↓
[0012] Production Readiness
```

---

## Stage 0001 — Foundation (`COMPLETED`)
- **Goal:** Establish a clean, buildable monorepo foundation, shared TypeScript packages, ethical security charter, `GET /api/health` endpoint, and dark cybersecurity Web Console shell with mock dashboard data.
- **Features:**
  - Monorepo workspaces (`apps/*`, `packages/*`), `@vajra/shared-types`, `@vajra/security`, `@vajra/config`.
  - Express API serving `GET /api/health` (`{"status":"ok","service":"vajra-api"}`).
  - React 19 + Tailwind CSS + Vite Web Console shell with clearly labeled mock telemetry (`ASUS TUF F16`, `Android Phone`).
- **Dependencies:** None (Initial stage).
- **Security Requirements:** Zero hardcoded secrets, `.env.example` placeholders, `PROHIBITED_CAPABILITIES` enforcement, `sanitizeLogMetadata()`.
- **Acceptance Criteria:** `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` all pass with zero errors.

---

## Stage 0002 — Product & Security Specification (`COMPLETED — CURRENT`)
- **Goal:** Define the complete product requirements, three-plane security architecture, event taxonomy, device lifecycle, threat check design, risk engine, database entities, API contracts, and platform boundaries before writing live device features.
- **Features:**
  - Complete documentation suite across `docs/product/*`, `docs/architecture/*`, `docs/security/*`, `docs/api/*`, and `docs/platform/*`.
  - Reconciled architecture index in root `README.md`.
- **Dependencies:** Stage 0001.
- **Security Requirements:** No premature implementation of surveillance, remote commands, or unverified endpoints; explicit OS permission respect and epistemic honesty rules (`ThreatCheck`, `IP_APPROXIMATE` location).
- **Acceptance Criteria:** All 19 new/updated specification documents complete, consistent with `React + Vite + Express` runtime, and all Stage 0001 verification gates passing.

---

## Stage 0003 — Database + Authentication Foundation (`PLANNED`)
- **Goal:** Initialize the relational database schema (`PostgreSQL` / `Prisma`) and implement Plane 1 User Authentication and the tamper-evident `AuditLog`.
- **Features:**
  - Prisma schema and migrations for core entities (`User`, `UserCredential`, `DeviceSession`, `RecoveryProfile`, `AuditLog`).
  - `/api/auth/login`, `/api/auth/logout`, `/api/auth/session`, and WebAuthn Passkey / Argon2id + MFA verification.
  - Short-lived, rotated `__Host-vajra_session` cookie middleware and CSRF protection.
  - Hash-chained `AuditLog` service and `/api/audit` viewer endpoint.
- **Dependencies:** Stage 0002.
- **Security Requirements:** Argon2id password hashing, SHA-256 session token hashing, rate limiting (`5 attempts / 15m`), constant-time comparisons, and verified `previousEntryHash -> entryHash` audit chain.
- **Acceptance Criteria:** Unauthenticated requests to protected routes return `401`; brute-force attempts trigger `423/429`; every auth event writes a verified hash-chained `AuditLog` entry.

---

## Stage 0004 — Device Identity & Enrollment (`PLANNED`)
- **Goal:** Implement Plane 2 Cryptographic Device Identity (`Device`, `DeviceCredential`) and the end-to-end device enrollment ceremony.
- **Features:**
  - `/api/devices`, `/api/devices/:id`, `/api/devices/enrollment`, and `/api/devices/:id/revoke`.
  - Single-use, 10-minute enrollment token generation (QR and alphanumeric pairing code).
  - Proof-of-Possession signature verification (`Ed25519` / `ECDSA P-256`) and user confirmation step (`ENROLLMENT_PENDING -> TRUSTED`).
  - Device lifecycle state machine (`UNREGISTERED` through `REVOKED` / `DECOMMISSIONED`).
- **Dependencies:** Stage 0003.
- **Security Requirements:** Private keys never sent to server; enrollment tokens stored as SHA-256 hashes; revoked devices immediately rejected (`403 DEVICE_REVOKED`).
- **Acceptance Criteria:** A device cannot reach `TRUSTED` state without valid user session + valid unexpired token + verified Proof-of-Possession signature + explicit user confirmation.

---

## Stage 0005 — Windows Agent (`PLANNED`)
- **Goal:** Build the C# / .NET 8+ Windows Service (`apps/windows-agent`) for hardware-backed enrollment, signed heartbeats, and legitimate Windows security telemetry.
- **Features:**
  - Windows CNG / TPM 2.0 non-exportable keypair generation and pairing client.
  - Periodic signed heartbeats (`60s` interval) and local bounded offline event ring buffer.
  - Windows Event Log watchers for logon/logoff (`4624`, `4625`), lock/unlock (`4800`, `4801`), Windows Defender (`5001`, `1116`), USB arrival, and network profile changes.
  - Signed graceful shutdown event (`SECURITY_AGENT_STOPPED`).
- **Dependencies:** Stage 0004.
- **Security Requirements:** Dedicated least-privilege service account (`NT SERVICE\VajraGuardService`), strict NTFS ACLs, zero keylogging/password/file collection, 100% Windows Defender compatibility.
- **Acceptance Criteria:** Windows Agent enrolls, signs heartbeats, buffers events while offline, and passes negative tests confirming zero prohibited capabilities exist.

---

## Stage 0006 — Android Application (`PLANNED`)
- **Goal:** Build the native Kotlin Android app (`apps/android`) with Android Keystore identity, signed heartbeats, permission-aware status, and `VAJRA Locate` foundation.
- **Features:**
  - `AndroidKeyStore` hardware-backed keypair generation and QR/code enrollment UI.
  - `WorkManager` periodic signed heartbeat reporting battery level, network transport, Keyguard lock status, and Play Protect / ADB status.
  - Opt-in `VAJRA Locate` coordinate capture (`ANDROID_FUSED_GPS`, `ANDROID_NETWORK`) with explicit `PermissionState` and AES-256-GCM application-layer encryption.
- **Dependencies:** Stage 0004.
- **Security Requirements:** Strict compliance with Android 10–15 runtime permissions; graceful degradation when permissions are denied; zero audio/camera/SMS/Accessibility permissions.
- **Acceptance Criteria:** App enrolls via `AndroidKeyStore`, reports accurate `PermissionState`, encrypts location payloads, and never misrepresents `IP_APPROXIMATE` as GPS.

---

## Stage 0007 — Event & Alert System (`PLANNED`)
- **Goal:** Implement the canonical Security Event ingestion pipeline (`/api/events`), Security Timeline UI, Backend Heartbeat Watchdog, and deduplicated Alert system (`/api/alerts`).
- **Features:**
  - Signed telemetry ingestion (`POST /api/events`) with schema validation and `sanitizeLogMetadata()`.
  - Cursor-paginated, multi-filter Security Timeline (`GET /api/events`) with burst coalescing.
  - Heartbeat Watchdog transitioning silent devices `ACTIVE -> OFFLINE` and raising alerts.
  - Alert creation, `dedupKey` cooldown coalescing, priority sorting, and user acknowledgement (`POST /api/alerts/:id/acknowledge`).
- **Dependencies:** Stages 0004, 0005, 0006.
- **Security Requirements:** Reject unsigned or replayed events; prevent `COMPROMISED` devices from auto-resolving alerts; log alert acknowledgements in `AuditLog`.
- **Acceptance Criteria:** Repeated identical events coalesce into a single deduplicated alert; timeline filters by device, severity, and category with zero sensitive data leakage.

---

## Stage 0008 — Device Recovery (`PLANNED`)
- **Goal:** Implement Plane 3 Command Authorization (`/api/devices/:id/commands`), remote phone ringing (`RING_PHONE`), Lost Mode (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`), and the Android Custom Recovery Screen.
- **Features:**
  - Step-up authentication check (`stepUpVerifiedUntil`) for sensitive commands.
  - Command signing authority, 128-bit cryptographic nonces, TTL expiration sweeps, and signed `CommandResult` verification.
  - Android `RING_PHONE` execution (`STREAM_ALARM` + stop notification) and `RecoveryActivity` Custom Recovery Screen (`Owner Name`, `Recovery Contact`, `Masked Device ID`).
- **Dependencies:** Stages 0006, 0007.
- **Security Requirements:** Strict allowlist enforcement (rejecting `EXECUTE_SHELL`, etc.); replay cache on server and agent; local Lost Mode dismissal requires Android OS Keyguard unlock.
- **Acceptance Criteria:** Commands without step-up auth, with expired TTL, or with replayed nonces are rejected; every command creates a synchronous `AuditLog` entry before dispatch.

---

## Stage 0009 — ThreatCheck (`PLANNED`)
- **Goal:** Implement the ThreatCheck URL analysis engine (`/api/threatcheck/url`), secret redaction pipeline, SSRF protection, and `ThreatIntelProvider` adapter architecture.
- **Features:**
  - `redactUrlSecrets()` query-parameter redaction before persistence or external lookup.
  - Stage 1 lexical/homograph/IP/shortener analyzer (`LocalHeuristicProvider`), Stage 2 passive DNS/domain context, and Stage 3 `ThreatIntelProvider` interface.
  - Web Console ThreatCheck view with evidence breakdown and history management.
- **Dependencies:** Stage 0003, 0007.
- **Security Requirements:** Block RFC 1918, loopback, and cloud metadata IPs (`SSRF_BLOCKED_TARGET`); never output *"100% safe"*; prohibit unauthorized intrusive scanning.
- **Acceptance Criteria:** Passes the full ThreatCheck fixture matrix (Punycode, IP URLs, shorteners, SSRF attempts, and `?token=SECRET` redaction).

---

## Stage 0010 — Risk Engine (`PLANNED`)
- **Goal:** Implement the deterministic, explainable VAJRA Risk Engine (`RiskAssessment`) and live dashboard posture scoring.
- **Features:**
  - Weighted rule evaluation across `Security Events`, `Device State`, `Authentication Events`, `ThreatCheck Results`, `Tamper Signals`, `Location Changes`, and `Device Trust State`.
  - Structured `RiskAssessment` output (`0–100` score, `LOW/MEDIUM/HIGH/CRITICAL` level, itemized `reasons[]`, and `recommendedAction`).
  - Replacement of mock dashboard scorecards with live database-backed posture metrics (while retaining clearly labeled demo mode if zero devices are enrolled).
- **Dependencies:** Stages 0007, 0008, 0009.
- **Security Requirements:** 100% deterministic and explainable point breakdown; no opaque or hallucinated scores.
- **Acceptance Criteria:** Every risk score point is traceable to a specific rule ID and source event ID; resolving the underlying issue decays/resets the score deterministically.

---

## Stage 0011 — Security Hardening (`PLANNED`)
- **Goal:** Execute comprehensive adversarial testing, cryptographic key rotation workflows, retention cleanup jobs, and Content Security Policy (CSP) hardening.
- **Features:**
  - Automated data retention scheduler enforcing TTLs (`LocationRecord` 7d/10-cap, `DeviceSession` 7d, `ThreatCheck` 30d, `SecurityEvent` 90d, `AuditLog` 365d).
  - Full negative security test suite (Plane 1/2/3 boundary fuzzing, signature tampering, replay attacks, SSRF bypass tests, rate-limit stress tests).
  - Strict HTTP security headers (`Content-Security-Policy`, `Permissions-Policy`, `Strict-Transport-Security`).
- **Dependencies:** Stages 0003–0010.
- **Security Requirements:** Zero high/critical findings across all 8 threat-model scenarios (`docs/security/threat-model.md`).
- **Acceptance Criteria:** All unit, integration, platform, and adversarial security tests pass with 100% boundary enforcement.

---

## Stage 0012 — Production Readiness (`PLANNED`)
- **Goal:** Finalize deployment packaging, user onboarding guides, self-service data export/account deletion, and operational runbooks.
- **Features:**
  - Signed Windows Agent installer packaging and Android release build verification.
  - Self-service privacy controls (Timeline export, Location history purge, full cascading account deletion).
  - Production readiness verification checklist and operator runbooks in `infrastructure/`.
- **Dependencies:** Stage 0011.
- **Security Requirements:** Verified production environment validation (`@vajra/config`), zero debug leaks, and complete audit trail verification.
- **Acceptance Criteria:** Full end-to-end production build, test suite, and documentation audit pass.
