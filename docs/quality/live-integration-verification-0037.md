# VAJRA — Live Integration Verification & Test Recovery Report (Prompt 0037)

**Date:** 2026-10-12  
**Workspace:** `/tmp/vajra-durable` (linked to `/app/applet`)  
**Git Repository Status:** `.git` directory is absent (`fatal: not a git repository`); no commit hashes are claimed.

---

## 1. Executive Verdict by Verification Layer

| Priority | Verification Layer | Command / Runner | Actual Execution Status | Evidence Summary |
| :---: | :--- | :--- | :---: | :--- |
| **Baseline** | TypeScript Static Check, Vite Build, Prisma Schema Validation, Dependency Audit | `npm run lint`, `npm run build`, `npm run db:validate`, `npm run verify:audit` | **EXECUTED — PASS** | `tsc --noEmit` exit `0`; `prisma generate && vite build` exit `0`; `prisma validate` exit `0`; `npm audit` `0 vulnerabilities`. |
| **Baseline** | Unit & In-Memory API Suite (without PG) | `npm test` | **EXECUTED — PASS** | **76 pass / 0 fail / 1 skipped** (`PostgreSQL integration` suite explicitly marked `skipped` with `BLOCKED` reason when `VAJRA_PG_INTEGRATION` is unset). |
| **Priority 1** | **Live PostgreSQL 15 Integration (`PrismaIdentityRepository` + 5 SQL Migrations)** | `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://vajra_test:<REDACTED>@127.0.0.1:5432/vajra_test?schema=public" npm run test:pg` | **EXECUTED — PASS** | **7 pass / 0 fail / 0 skipped** (`tests/postgres-integration.test.ts`, `3914.58 ms`). All 5 migrations (`0003`–`0007`) applied to disposable `vajra_test` database. Combined suite with PG enabled: **82 pass / 0 fail / 0 skipped** across **27 suites**. |
| **Priority 2** | **Browser E2E Readiness & Headless Chromium Verification** | `tests/e2e/browser-e2e.test.ts` + `npm run test:e2e:browser` (`scripts/verify-browser-e2e.mjs`) | **PARTIAL (Playwright Chromium launch verified; full E2E suite authored; container rootfs reset during shared-lib extraction)** | `playwright-core` headless Chromium launch verified (`VAJRA Playwright OK`). Full 7-test browser E2E suite authored in `tests/e2e/browser-e2e.test.ts` and wired to `npm run test:e2e:browser`. Full 7-test browser run is **NOT CLAIMED as passed** in this container session because extracting system `.deb` shared libraries onto `/` broke the merged-`/lib` symlink before the full spec completed. |
| **Priority 3** | **Windows Agent Build & `Vajra.ProtocolParity` xUnit Suite** | `npm run test:windows-agent` (`scripts/verify-windows-agent.mjs`) | **BLOCKED / NOT RUN** | Host is `Linux x86_64` (`Debian 12`) and `.NET 8 SDK` (`dotnet`) is not installed. `Vajra.WindowsAgent.csproj` targets `net8.0-windows` (`UseWindowsService=true`, Windows DPAPI & `EventLogReader`). Script exits `2` (`BLOCKED`). |
| **Priority 4** | **Real-Device End-to-End Integration (Windows Agent / Android Companion)** | Real `Vajra.WindowsAgent` or Android APK against Express + PostgreSQL | **BLOCKED / NOT RUN** | Requires a physical/VM Windows 10 22H2+ / 11 host or Android device/emulator. In-memory or Node protocol-client tests are **not** claimed as real device execution. |

---

## 2. Test Inventory Investigation (`90` vs `77` vs `76` vs `82` Tests)

### Exact Enumeration of Discovered Test Files in `/tmp/vajra-durable`

#### A. Node / TypeScript Test Suite (`tests/*.test.ts` — matched by `npm test`)

| # | Test File | `describe` Suites | `it` Test Cases (when `VAJRA_PG_INTEGRATION` unset) | `it` Test Cases (when `VAJRA_PG_INTEGRATION=1`) | Scope |
| :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `tests/auth-foundation.test.ts` | 5 | 7 | 7 | Argon2id, registration, login, session cookies, CSRF, lockout, TOTP MFA, audit chain |
| 2 | `tests/database-foundation.test.ts` | 1 | 4 | 4 | Prisma schema models, indexes, migrations `0003`–`0005`, repository contract |
| 3 | `tests/device-enrollment.test.ts` | 2 | 4 | 4 | Enrollment initiate/submit/confirm, Ed25519 & ECDSA P-256 PoP, Plane-2 device auth, nonce replay |
| 4 | `tests/foundation.test.ts` | 1 | 4 | 4 | Monorepo health, security invariants, shared types |
| 5 | `tests/postgres-integration.test.ts` | 2 | **1** (`skipped` suite + 1 source check) | **7** (6 live PG tests + 1 source check) | Live `PrismaIdentityRepository` + PostgreSQL 15 migrations, constraints, triggers, and fail-closed config |
| 6 | `tests/prompt0007.test.ts` | 1 | 4 | 4 | Notifications, activity timeline, allowlisted device actions, step-up gating |
| 7 | `tests/prompt0008.test.ts` | 1 | 8 | 8 | Event engine, risk scoring, command state machine (`QUEUED` -> `DELIVERED` -> `ACKNOWLEDGED` -> `COMPLETED`), ThreatCheck |
| 8 | `tests/prompt0011b.test.ts` | 1 | 7 | 7 | ThreatCheck URL canonicalization, secret redaction, SSRF/private IP flagging, history pagination |
| 9 | `tests/prompt0011c.test.ts` | 1 | 3 | 3 | Security headers, rate limiting, production startup fail-closed validation |
| 10 | `tests/prompt0011d.test.ts` | 3 | 11 | 11 | Step-up MFA scope binding (`DEVICE_REVOKE`, `ENABLE_LOST_MODE`, `SENSITIVE_COMMAND`), single-use consumption |
| 11 | `tests/prompt0012-analytics.test.ts` | 2 | 6 | 6 | Persisted security analytics summary (`PERSISTED` dataSource), JSON/CSV export, CSV formula-injection defense |
| 12 | `tests/prompt0016-protocol-parity.test.ts` | 4 | 7 | 7 | Canonical JSON RFC 8785 ordering, DER ECDSA P-256 signature parity across Node, Windows C#, and Android Kotlin |
| 13 | `tests/prompt0028-inventory-demo.test.ts` | 2 | 4 | 4 | Honest empty device inventory, opt-in `showSampleDevicePreview`, `/api/demo/events` production gate |
| 14 | `tests/ui-abstraction.test.ts` | 1 | 6 | 6 | Calm human-readable product copy, 5-layer Vajra atmosphere, UI primitives |
| — | **Total (`tests/*.test.ts`)** | **27 suites** | **76 pass + 1 skipped (77 total)** | **82 pass + 0 skipped (82 total)** | — |

#### B. Additional Platform & Browser Suites in the Repository

| Suite | File Path | Test Cases | Runner |
| :--- | :--- | :---: | :--- |
| **Browser E2E Suite** | `tests/e2e/browser-e2e.test.ts` | **7** `it` cases | `npm run test:e2e:browser` (`scripts/verify-browser-e2e.mjs`) |
| **Windows Agent Protocol Parity (xUnit)** | `apps/windows-agent/tests/Vajra.ProtocolParity/CanonicalAndDerTests.cs` | **6** `[Fact]` cases | `npm run test:windows-agent` (`dotnet test`) |
| **Android Companion Crypto Parity (JUnit)** | `apps/android/app/src/test/java/com/vajra/companion/crypto/DeviceRequestSignerTest.kt` | **5** `@Test` cases | `./gradlew testDebugUnitTest` |

### Why the Test Count Changed (`90` vs `77` vs `76` vs `82`)

1. **`77` -> `76` passing tests when PostgreSQL is not enabled:**
   - Before Prompt 0036, `tests/postgres-integration.test.ts` contained an `if (!runPgIntegration)` branch with a single dummy test (`it('skips live PostgreSQL tests...', () => { assert.ok(true); })`), which Node's test runner counted as a passing test (`76 + 1 = 77 pass, 0 skipped`).
   - In Prompt 0036, to enforce strict reporting honesty (never converting a skipped/blocked test into a pass), that stub was replaced with `{ skip: 'BLOCKED: Missing prerequisite...' }` on the `describe` block. When `VAJRA_PG_INTEGRATION=1` is not set, `npm test` therefore reports **`76 pass / 0 fail / 1 skipped`**.
2. **`76` -> `82` passing tests when PostgreSQL IS enabled (`VAJRA_PG_INTEGRATION=1`):**
   - When `VAJRA_PG_INTEGRATION=1` and a live disposable PostgreSQL `DATABASE_URL` are provided, `tests/postgres-integration.test.ts` executes all **6** live database integration `it(...)` blocks plus the **1** production fail-closed test (`7` tests in `tests/postgres-integration.test.ts`), bringing the total executed in `tests/*.test.ts` to **`82` tests across `27` suites**.
3. **Why an earlier report referenced `90` tests:**
   - As documented in `artifacts/device-integration-0031.md` and `artifacts/device-integration-0032.md`, the imported workspace archive (`attachments/vajra-personal-security-complete.zip`) was snapshotted after Prompt 0028 (`14` test files, `77` tests without PG / `82` tests with PG). Additional test files created in an unarchived ephemeral container between Prompts 0029 and 0035 were not present in `vajra-personal-security-complete.zip`. No tests were excluded by runner globs in `/tmp/vajra-durable`, and per Prompt 0037 rules, no synthetic unit tests were invented to inflate the count.

---

## 3. Priority 1: Live PostgreSQL Integration Verification (`EXECUTED — PASS`)

### Disposable PostgreSQL 15 Setup & Safety Guard Verification

1. **Local Cluster Initialization:**
   - Provisioned PostgreSQL 15 binaries (`/usr/lib/postgresql/15/bin/postgres`, `initdb`, `pg_ctl`, `psql`, `pg_isready`) and initialized an isolated disposable cluster at `/tmp/pgdata-vajra-test` (socket `/tmp/pgsock-vajra-test`, listening only on loopback `127.0.0.1:5432`).
   - Created a test-only role `vajra_test` and disposable database `vajra_test`.
2. **Safety Guard Checks (`scripts/verify-pg.mjs`):**
   - Verified `npm run test:pg` without `VAJRA_PG_INTEGRATION=1` exits with code `2`:
     `BLOCKED [test:pg]: Missing prerequisite: VAJRA_PG_INTEGRATION=1 is not set.`
   - Verified `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://vajra_user:<REDACTED>@127.0.0.1:5432/vajra_prod" npm run test:pg` exits with code `2`:
     `BLOCKED [test:pg]: Safety check failed: Disposable test database name must contain "test" (found "vajra_prod").`
3. **Prisma Migrations Applied to `vajra_test`:**
   - `0003_identity_foundation`
   - `0004_complete_schema_foundation`
   - `0005_rdbms_views_triggers_procedures` (including `trg_prevent_audit_log_mutation` and SQL views)
   - `0006_step_up_action_scope`
   - `0007_analytics_query_indexes`
   - Result: `All migrations have been successfully applied.` (`18` tables verified in `public` schema).

### Executed PostgreSQL Integration Suite Results (`npm run test:pg`)

Command:
```bash
VAJRA_PG_INTEGRATION=1 \
DATABASE_URL="postgresql://vajra_test:<REDACTED_TEST_PW>@127.0.0.1:5432/vajra_test?schema=public" \
npm run test:pg
```

Exit Code: **`0`** (`# tests 7, # suites 2, # pass 7, # fail 0, # skipped 0, duration_ms 3914.58`)

| # | Test Case in `tests/postgres-integration.test.ts` | Status | Duration | Verified PostgreSQL Operations |
| :---: | :--- | :---: | :---: | :--- |
| 1 | `reports PostgreSQL backend health on readiness` | **PASS** | `19.45 ms` | `repo.checkDatabaseHealth()` returns `{ ok: true, backend: 'POSTGRESQL_PRISMA' }`; `GET /api/ready` returns `200`. |
| 2 | `registers a user and rejects duplicate email (unique constraint)` | **PASS** | `95.29 ms` | `POST /api/auth/register` persists `User` + Argon2id `UserCredential` + `DeviceSession` + `AuditLog` (`201`); duplicate email rejected (`409`) via PostgreSQL unique constraint. |
| 3 | `persists session, enables MFA, and grants action-scoped step-up` | **PASS** | `68.12 ms` | AES-256-GCM encrypted TOTP secret persisted on `UserCredential`; `POST /api/auth/step-up` verifies TOTP and persists `stepUpVerifiedAt` + `stepUpActionScope = 'DEVICE_REVOKE'` on `DeviceSession`. |
| 4 | `enrolls a device through pending → confirm and rejects cross-user access` | **PASS** | `380.42 ms` | Full lifecycle in PostgreSQL: `initiate` (`201`, `EnrollmentChallenge` row) -> `submit` (`200`, Ed25519 PoP verified, `DeviceCredential` row) -> `confirm` (`200`, `Device.lifecycleState = 'TRUSTED'`, `DeviceCredential.status = 'ACTIVE'`). Cross-user `GET /api/devices/:id` rejected (`404`/`403`). Signed Plane-2 `POST /api/devices/:id/heartbeat` (`200`) persists `DeviceHeartbeat` and `DeviceAuthNonce` rows; replaying the same nonce returns `409 DEVICE_NONCE_REPLAYED`. Full command lifecycle: `POST /api/devices/:id/commands` (`REQUEST_DEVICE_STATUS` -> `201 QUEUED`) -> `GET /commands/pending` (`200`) -> `POST /commands/:cmdId/acknowledge` (`200`) -> `POST /commands/:cmdId/result` (`200 COMPLETED`), verifying persisted `RemoteCommand.status = 'COMPLETED'` and `CommandResult` row in PostgreSQL. |
| 5 | `returns analytics from persisted records with PERSISTED dataSource` | **PASS** | `105.06 ms` | `POST /api/threatcheck/inspect` persists redacted `ThreatCheck` and `ThreatIndicator` rows; `GET /api/analytics/summary` returns `200` with `dataSource: 'PERSISTED'` and `threatChecks.totalCount >= 1`. |
| 6 | `enforces append-only AuditLog at the database layer` | **PASS** | `37.50 ms` | Direct SQL `UPDATE "AuditLog"` and `DELETE FROM "AuditLog"` are both rejected by PostgreSQL trigger `trg_prevent_audit_log_mutation` (`VAJRA_AUDIT_IMMUTABLE`); `verifyAuditChain(await repo.getAllAuditEventsOrdered())` returns `{ valid: true }`. |
| 7 | `server.ts rejects production without a real DATABASE_URL` | **PASS** | `0.79 ms` | Confirms fail-closed production startup guards in `server.ts`. |

---

## 4. Priority 2: Browser E2E Suite & Accessibility Improvements

### Code & Test Additions
1. **Dialog Accessibility (`src/components/VajraUiPrimitives.tsx`):**
   - Verified `useDialogAccessibility(open, onClose)` on `Modal`, `DetailDrawer`, and `NotificationSlideOverPanel` providing `role="dialog"`, `aria-modal="true"`, `aria-labelledby`, initial focus placement, `Tab`/`Shift+Tab` focus containment, `Escape` key dismissal, and focus restoration to the invoking trigger.
2. **Automated Browser E2E Suite (`tests/e2e/browser-e2e.test.ts` & `scripts/verify-browser-e2e.mjs`):**
   - Authored a 7-test real headless Chromium E2E suite in `tests/e2e/browser-e2e.test.ts` using `playwright-core` against an isolated Express + built SPA (`dist/`) server instance covering:
     1. Owner registration, authenticated Overview load, sign-out, and sign-in.
     2. Honest empty device inventory (`0` enrolled devices, no `ASUS TUF F16` shown as real) and opt-in `Show sample preview` / `Hide sample preview` toggle.
     3. Keyboard-accessible dialogs (`Modal` and `NotificationSlideOverPanel` with `role="dialog"`, `aria-modal="true"`, `Tab`/`Shift+Tab` focus trap, `Escape` dismissal) and mobile viewport (`375x812`) zero horizontal overflow check.
     4. Two-step verification (TOTP setup, 8 single-use recovery codes, and MFA login challenge).
     5. ThreatCheck URL inspection (`http://127.0.0.1:8080/admin?access_token=SECRET123#frag`), query secret redaction (`access_token=[REDACTED]`), restricted destination alert, explainable indicators, and lexical limitation notice.
     6. Windows device enrollment (`ECDSA_P256`), real inventory card rendering, `DetailDrawer` inspection, `REQUEST_DEVICE_STATUS` queueing (`Waiting for device agent delivery`), and `Escape` drawer dismissal.
     7. Persisted Security Analytics & JSON/CSV report export (`Cache-Control: no-store`).
3. **Honest Execution Status:**
   - Headless Chromium launch via `playwright-core` was verified (`Browser title/text: VAJRA Playwright OK`), and `npx playwright install chromium --only-shell` downloaded `chromium_headless_shell-1248`.
   - However, during the subsequent `.deb` shared-library extraction step in the container, running `dpkg-deb -x "$deb" /` on Debian 12 (merged-`/usr`) overwrote the `/lib -> usr/lib` symlink before `tests/e2e/browser-e2e.test.ts` executed. Therefore, **full execution of `tests/e2e/browser-e2e.test.ts` is NOT claimed as passed in this session.**
   - **Safe container Note for future runs:** On merged-`/usr` Debian containers, never run `dpkg-deb -x <pkg>.deb /` directly onto `/`; always extract to `/tmp/deb-extract` and set `LD_LIBRARY_PATH=/tmp/deb-extract/usr/lib/x86_64-linux-gnu:/tmp/deb-extract/lib/x86_64-linux-gnu` or run `npx playwright install --with-deps chromium` on a standard developer machine.

---

## 5. Priority 3 & 4: Windows-Agent & Real-Device Verification Readiness (`BLOCKED / NOT RUN`)

- **Windows Agent Build & `Vajra.ProtocolParity` (`npm run test:windows-agent`):**
  - **Status:** **BLOCKED / NOT RUN** (Exit code `2`).
  - **Reason:** Host OS is `linux x64` and `.NET 8 SDK` (`dotnet`) is not installed. `apps/windows-agent/Vajra.WindowsAgent.csproj` targets `net8.0-windows` and uses Windows-only APIs (`ProtectedData` DPAPI and `EventLogReader`).
- **Real Windows Agent & Android Companion End-to-End Verification:**
  - **Status:** **BLOCKED / NOT RUN**.
  - **Reason:** Zero real `Vajra.WindowsAgent` or Android APK device processes were executed in this Linux container. The PostgreSQL command lifecycle verified in Section 3 used a Node cryptographic protocol client inside `tests/postgres-integration.test.ts` and is strictly classified as a **server + PostgreSQL protocol integration test**, not a real device agent run.
  - Follow the 10-step Windows verification procedure in `docs/quality/verification-readiness-0036.md` Section 7 on a Windows 10 22H2+ / Windows 11 workstation with `.NET 8 SDK` and local PostgreSQL 14+.
