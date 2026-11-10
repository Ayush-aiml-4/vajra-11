# VAJRA — Source-Grounded Functional Requirements Audit (Prompt 0051)

**Workspace Inspected:** Current repository root (Node `v22.23.4`, npm `10.9.9`; `.git` directory not present in container)  
**Verification Executed in Run:** `npm run lint`, `npm run typecheck`, `npm run db:validate`, `npm run verify:audit`, `npm run build`, `npm test` (`113/113` pass), `DATABASE_URL="" npm run test:e2e:browser` (`9/9` pass), `./infrastructure/scripts/azure-preflight.sh` (pass)  
**Classification Legend:** `IMPLEMENTED` · `PARTIAL` · `MOCKED` · `BLOCKED` · `NOT IMPLEMENTED` · `VERIFIED IN THIS RUN`

---

## 1. Authentication, Sessions & Account Lifecycle

| Capability | Status | Evidence & Verification | Remaining Scope Notes |
| :--- | :---: | :--- | :--- |
| Owner registration (`POST /api/auth/register`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Argon2id password hashing, password policy enforcement, session issuance; verified in unit + Chromium E2E tests | — |
| Sign-in, sign-out & session restoration (`/api/auth/login`, `/logout`, `/me`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `__Host-vajra_session` (`SameSite=None; Secure; Partitioned`) over HTTPS & `vajra_session` (`SameSite=Lax`) on plain HTTP localhost; resilient against gateway warmup HTML; verified in unit + cross-site iframe Chromium E2E test | — |
| TOTP MFA setup, disable & 8 single-use recovery codes | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | AES-256-GCM encrypted TOTP secret, SHA-256 hashed single-use recovery codes, session revocation on recovery login / disable / regenerate; verified in `prompt0049`, `prompt0050`, and Chromium E2E test 4 | — |
| Action-scoped MFA step-up (`POST /api/auth/step-up`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | 5-minute TTL, scope-bound (`DEVICE_REVOKE`, `DEVICE_COMPROMISED`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `SENSITIVE_COMMAND`), single-use consumption; verified in unit + Chromium E2E test 6 | — |
| Active session listing & per-session revocation (`/api/auth/sessions*`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/auth/routes.ts` + Settings UI session list; cross-user IDs return `404 SESSION_NOT_FOUND` | — |
| Password change & account deletion | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `POST /api/auth/password/change` & `POST /api/auth/account/delete` require current password (+ MFA when enabled) | — |
| WebAuthn / Passkey runtime login ceremonies | `NOT IMPLEMENTED` | `PasskeyCredential` Prisma table exists; runtime WebAuthn assertion routes/UI are not implemented | Documented honestly in `README.md` & `docs/api/endpoints.md` |

---

## 2. Device Enrollment, Identity & Lifecycle

| Capability | Status | Evidence & Verification | Remaining Scope Notes |
| :--- | :---: | :--- | :--- |
| Device inventory (`GET /api/devices`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Empty-by-default inventory; cross-user isolation (`404`); verified in unit + Chromium E2E test 2 | Opt-in sample preview (`MOCKED`) clearly labeled and non-persistent |
| 3-step enrollment ceremony (`initiate` -> `submit` -> `confirm`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Single-use hashed pairing token (10m TTL), ECDSA P-256 Proof-of-Possession, duplicate key rejection (`409 DUPLICATE_PUBLIC_KEY`), owner step-up confirmation; verified in unit + Chromium E2E tests 6 & 8 | — |
| Signed Plane-2 heartbeats & battery history | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `POST /api/devices/:id/heartbeat` (`VAJRA-DEVICE-AUTH-V1`, ±120s window, atomic nonce replay `409`), `GET /api/devices/:id/battery-history` (Android 24h window) | Live physical agent -> DB execution `BLOCKED` by host toolchains here |
| Revoke, compromised & decommission transitions | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `revoke` and `decommission` revoke credentials and automatically cancel pending `RemoteCommand`s; fresh-keypair re-enrollment verified in `prompt0051-security-gap-closure.test.ts` | — |

---

## 3. Guard, Alerts, Activity & Audit Chain

| Capability | Status | Evidence & Verification | Remaining Scope Notes |
| :--- | :---: | :--- | :--- |
| Signed device security event ingestion (`POST /api/devices/:id/events`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Route-bound Plane-2 verification, prohibited field sanitization, deterministic `0–100` risk scoring, deduplicated alert creation | — |
| Notifications & Security Activity feed | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Read, read-all, acknowledge, dismiss + calm human-readable audit mapping in `src/App.tsx` | — |
| Tamper-evident SHA-256 audit chain (`/api/audit/verify`) | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Verified via tamper-detection tests (`prompt0049`) + PostgreSQL append-only trigger (`0005_audit_log_immutability`) | — |
| Demo event seeding (`/api/demo/*`) | `MOCKED` (Dev/Test Only) | Hard-disabled (`404 DEMO_DISABLED`) in production or when `VAJRA_ENABLE_DEMO_ENDPOINTS=false` | — |

---

## 4. Locate & Remote Recovery Actions

| Capability | Status | Evidence & Verification | Remaining Scope Notes |
| :--- | :---: | :--- | :--- |
| `REQUEST_DEVICE_STATUS` | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Queued for Windows & Android; stays `QUEUED` until signed Plane-2 receipt (`acknowledge` -> `result`); terminal state immutable | — |
| `RING_DEVICE` | `IMPLEMENTED` (Android Only) / `VERIFIED IN THIS RUN` | Allowed on `ANDROID` (step-up gated, receipt-driven); rejected on `WINDOWS` with `400 UNSUPPORTED_COMMAND_FOR_PLATFORM` and disabled in UI | — |
| `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` | `PARTIAL` (Account State) / `VERIFIED IN THIS RUN` | Updates server-side VAJRA device lifecycle (`LOST` <-> `ACTIVE`/`TRUSTED`) with `executionScope: 'SERVER_ACCOUNT_STATE'`, `physicalLockApplied: false`, `liveLocationTracking: false`; never fabricates `ONLINE` status or `lastSeenAt` | Does **not** lock OS screens or track GPS |
| `REQUEST_LOCATION` (Live GPS / Locate) | `NOT IMPLEMENTED` | Rejected server-side (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) and disabled on enrolled devices in UI; never fakes IP geolocation as GPS | — |
| `DISPLAY_RECOVERY_MESSAGE` (On-device lock banner) | `NOT IMPLEMENTED` | Rejected server-side (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) and disabled on enrolled devices in UI | — |

---

## 5. ThreatCheck, Analytics & Reporting

| Capability | Status | Evidence & Verification | Remaining Scope Notes |
| :--- | :---: | :--- | :--- |
| ThreatCheck URL inspection & history | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Zero outbound network fetches (SSRF-safe), secret query/fragment redaction, explainable indicators, honest limitations banner; verified in unit + Chromium E2E test 5 | Lexical/destination analysis only (no external third-party feed configured) |
| Persisted Security Analytics & JSON/CSV export | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `GET /api/analytics/summary` (`dataSource: "PERSISTED"`), `GET /api/reports/export` with `escapeCsvCellSafe` formula neutralization; verified in unit + Chromium E2E test 7 | — |

---

## 6. Native Agents, PostgreSQL Runtime & Cloud Deployment

| Subsystem | Code Status | Current Container Execution Status | Exact Blocker on Current Linux Container |
| :--- | :---: | :---: | :--- |
| Windows Worker Service (`apps/windows-agent`) | `IMPLEMENTED` | `BLOCKED` (`Exit 2`) | Requires Windows 10 22H2+/11 host + `.NET 8 SDK` (`dotnet` absent) |
| Android Companion (`apps/android`) — incl. fresh Keystore `rotateKey()` on re-enrollment | `IMPLEMENTED` | `BLOCKED` (`Exit 2`) | Requires `JDK 17` + `Android SDK Platform 34` (`java`/SDK absent) |
| PostgreSQL Prisma schema (`0003`–`0007`) & backup/restore scripts | `IMPLEMENTED` (`db:validate` PASS) | `BLOCKED` (`Exit 2` for live `test:pg`) | No local PostgreSQL daemon running on `127.0.0.1:5432` (`psql`/`postgres` absent) |
| Azure App Service + PostgreSQL + Key Vault (`infrastructure/azure/main.bicep`) | `IMPLEMENTED` (`azure-preflight.sh` PASS) | `BLOCKED` (Not Provisioned) | `az`/`bicep` CLI absent; live cloud deployment prohibited by safety rules |
