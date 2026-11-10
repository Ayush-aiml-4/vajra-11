# VAJRA — Prompt 0046: Close Verification Gaps and Establish a Release-Ready Baseline

**Report Date:** 2026-10-28  
**Scope:** Integration verification closure, lockfile & security audit stabilization (`GAP-AUDIT-01`), safe disposable PostgreSQL verification (`GAP-PG-01`), browser E2E claim & data-source validation, UI modal-stacking bug repair, and native agent build readiness assessment (`GAP-WIN-01`, `GAP-AND-01`, `GAP-AZ-01`).  
**Constraints Respected:** No product features added, no UI redesign, no Azure deployment performed, existing `bun.lock` and prior reports preserved, no secrets or full database connection strings printed.

---

## 1. Executive Summary & Issues Resolved

All verification gaps solvable within a Linux x64 workstation/container environment have been closed with reproducible command-level evidence, and one genuine frontend interaction defect uncovered by expanded browser E2E testing was fixed:

1. **Resolved `GAP-AUDIT-01` (Lockfile & Dependency Vulnerability Audit)**:
   - Confirmed **npm** (`10.9.9`) is the repository's canonical dependency manager (`package.json` `verify:audit`, `.npmrc`, `README.md`, `CONTRIBUTING.md`, `docs/deployment/*`), while the container bootstrapper had previously run `bun install` (`bun 1.4.4`), creating `bun.lock` and `node_modules/.bun/`.
   - Generated `/package-lock.json` (`lockfileVersion: 3`, matching `package.json` without upgrading unrelated dependencies) while preserving `/bun.lock` untouched.
   - Verified clean reproducible installation via `npm ci --legacy-peer-deps` in an isolated workspace copy (`added 298 packages, and audited 302 packages`, `prisma generate` succeeded, exit code `0`).
   - Executed `npm audit --registry https://registry.npmjs.org` (`0 vulnerabilities`, exit code `0`) and `bun audit` (`No vulnerabilities found (checked 375 packages)`, exit code `0`).
2. **Resolved `GAP-PG-01` (Safe Disposable PostgreSQL Integration Verification)**:
   - Provisioned an isolated loopback-only PostgreSQL `15.19` (`15.19-0+deb12u1`) cluster at `/tmp/pgdata-vajra-test` bound strictly to `127.0.0.1:5432` with non-superuser role `vajra_test` and dedicated disposable database `vajra_test`.
   - Verified `scripts/verify-pg.mjs` fail-closed safety guards against missing `VAJRA_PG_INTEGRATION=1` (exit `2`), non-test database names such as `vajra_prod` (exit `2`), and `NODE_ENV=production` (exit `2`).
   - Applied all 5 forward-only SQL migrations (`0003`–`0007`) and ran `npm run test:pg`: **8 of 8 tests passed across 2 suites** (exit code `0`).
3. **Resolved Browser E2E Coverage Gaps & Fixed Real Lost Mode / MFA Step-Up Modal Defect**:
   - Audited `tests/e2e/browser-e2e.test.ts` against Prompt 0045's claims and closed four real gaps:
     1. Added explicit runtime logging of the active repository backend (`IN_MEMORY` vs `POSTGRESQL_PRISMA`).
     2. Extended Test 6 to complete signed Plane-2 command polling (`GET /commands/pending`), acknowledgement (`POST /acknowledge`), and authentic execution receipt (`POST /result`) and verified `State: COMPLETED` in the Device Detail Drawer.
     3. Extended Test 6 to actually click `Lost Mode` -> `Enable Lost Mode`, trigger `403 STEP_UP_REQUIRED` (`Scope: ENABLE_LOST_MODE`), submit a live 6-digit TOTP code in the browser modal, and verify Lost Mode activation (`Turn Off Lost Mode`).
     4. Added Test 8 to exercise the 3-step `Connect Device` browser wizard (`window.crypto.subtle` ECDSA P-256 key generation and DER proof signing) and—when backed by PostgreSQL—spin up a second independent Express + `PrismaClient` server instance to prove real database-boundary persistence across server restarts.
   - **Real Application Defect Discovered & Fixed (`src/App.tsx`)**: Submitting `Enable Lost Mode` when MFA step-up was required left `recoveryModalOpen` (`z-50`) open on top of `stepUpModalOpen` (`z-50`, rendered earlier in DOM order), intercepting pointer clicks on the Step-Up `Verify` button. Fixed in `src/App.tsx` by closing `recoveryModalOpen` when transitioning to `openStepUpForAction` (preserving `safePayload` for automatic post-step-up retry) and moving the MFA Step-Up `<Modal>` last in DOM order.
   - Ran `npm run test:e2e:browser` in **both** default `IN_MEMORY` mode (**8/8 passed**, exit `0`) and `POSTGRESQL_PRISMA` mode against `vajra_test` (**8/8 passed**, exit `0`).
4. **Executed Native Agent & Build Readiness Checks (`GAP-WIN-01`, `GAP-AND-01`)**:
   - Executed `npm run test:windows-agent` and `./apps/android/gradlew -p apps/android testDebugUnitTest assembleDebug` directly and recorded exact host/toolchain blockers without conflating Node protocol parity tests with native OS agent execution.

---

## 2. Files Changed and Rationale

| File Path | Change Type | Reason for Change |
|---|---|---|
| `/package-lock.json` | Created | Canonical npm v3 lockfile matching `package.json` & workspace `packages/*/package.json` without upgrading existing dependencies; unblocks `npm audit` (`GAP-AUDIT-01`) and clean `npm ci --legacy-peer-deps` builds while preserving `/bun.lock`. |
| `/src/App.tsx` | Modified | Fixed modal-stacking bug uncovered by E2E Test 6: closes `recoveryModalOpen` before opening `stepUpModalOpen` on `STEP_UP_REQUIRED` (`safePayload` retains recovery title/message/contact for automatic retry) and renders the MFA Step-Up `<Modal>` last in DOM order so it is never obscured by other modals. |
| `/tests/e2e/browser-e2e.test.ts` | Modified | Logs active repository backend (`IN_MEMORY` vs `POSTGRESQL_PRISMA`), verifies signed command poll -> ack -> authentic `COMPLETED` receipt in UI, exercises real `Lost Mode` -> `ENABLE_LOST_MODE` MFA step-up modal flow in Test 6, and adds Test 8 covering the 3-step `window.crypto.subtle` enrollment wizard plus cross-server PostgreSQL persistence verification. |
| `/docs/quality/integration-gap-review-0046.md` | Created | Authoritative Prompt 0046 verification closure and release-readiness baseline report. |

*(Existing files `/package.json`, `/bun.lock`, `/.npmrc`, `/docs/quality/integration-audit-0044.md`, and `/docs/quality/integration-gap-review-0045.md` were preserved unmodified.)*

---

## 3. Workspace, Lockfile, and Dependency Audit Status (`GAP-AUDIT-01`)

### Canonical Package Manager Analysis
- **Workspace Path**: `/app/applet` (imported archive from `Ayush-aiml-4/vajra-23`; `.git` directory is not present in the imported snapshot).
- **Canonical Package Manager**: **npm** (`10.9.9` on Node.js `v22.22.2`).
  - Evidence: `package.json` defines `"verify:audit": "npm audit --registry https://registry.npmjs.org"` and npm `workspaces: ["packages/*"]`; `.npmrc` configures npm registry settings; `README.md`, `CONTRIBUTING.md`, `docs/deployment/node-workspace-recovery.md`, and `docs/deployment/azure-app-service.md` standardize on `npm ci` / `npm run`.
- **Why `package-lock.json` Was Absent**: The container runtime initially hydrated `node_modules` with `bun install` (`bun 1.4.4`), producing `/bun.lock` (`97 KB`) and `node_modules/.bun/...` symlinks. Running `npm install --package-lock-only` directly inside a directory populated by `node_modules/.bun` triggers an `@npmcli/arborist` `#loadPeerSet` null-reference crash (`Cannot read properties of null (reading 'edgesOut')`), and Vite `^8.3.5` vs `@vitejs/plugin-react ^5.0.4` peer metadata requires `--legacy-peer-deps` in npm 10.
- **Resolution & Clean-Install Proof**:
  1. Generated `/package-lock.json` (`lockfileVersion: 3`, 5,924 lines) from exact `package.json`, `.npmrc`, and `packages/*/package.json` manifests in an isolated staging directory without `node_modules/.bun`, then copied `/package-lock.json` into the workspace root while keeping `/bun.lock` intact.
  2. Verified reproducible clean install in `/var/tmp/vajra-npm-clean` via `npm --prefix /var/tmp/vajra-npm-clean ci --legacy-peer-deps --registry https://registry.npmjs.org`:
     - Exit code: `0`
     - Output: `added 298 packages, and audited 302 packages in 16s`, `postinstall: prisma generate` generated Prisma Client `v6.19.3`, `found 0 vulnerabilities` (temporary staging directory removed afterward).
  3. Ran dependency security audits in `/app/applet`:
     - `npm audit --registry https://registry.npmjs.org` -> **Exit `0` (`found 0 vulnerabilities`)**
     - `npm run verify:audit` -> **Exit `0` (`found 0 vulnerabilities`)**
     - `bun audit` -> **Exit `0` (`No vulnerabilities found (checked 375 packages)`)**

---

## 4. Safe Disposable PostgreSQL Verification (`GAP-PG-01`)

### Database Identity & Isolation Classification
- **Server Package**: Official Debian 12 (`bookworm`) `postgresql-15` (`15.19-0+deb12u1`) installed via `apt-get` scoped strictly to `/etc/apt/sources.list.d/debian.sources` (no raw archive extraction over `/` and no dynamic-linker modifications).
- **Cluster Data Directory**: `/tmp/pgdata-vajra-test` (ephemeral local test cluster owned by unprivileged OS user `postgres`).
- **Network Binding**: Loopback-only `127.0.0.1:5432` (`listen_addresses = '127.0.0.1'`, `scram-sha-256` authentication; random ephemeral password stored mode `0600` outside repository and redacted as `<REDACTED>` in all logs/reports).
- **Confirmed SQL Identity Check**:
  - `version()`: `PostgreSQL 15.19 (Debian 15.19-0+deb12u1)`
  - `current_database()`: `vajra_test`
  - `current_user`: `vajra_test` (`rolsuper = false`, `rolcreatedb = false`)
  - `inet_server_addr()` / `inet_server_port()`: `127.0.0.1:5432`
  - Cluster databases present: `postgres`, `template0`, `template1`, `vajra_test` (zero production or user data).

### Safety Guard Verification (`scripts/verify-pg.mjs`)
Before running migrations, all built-in safety guards in `scripts/verify-pg.mjs` were tested and confirmed fail-closed:
1. Unset `VAJRA_PG_INTEGRATION` -> **Exit `2`** (`BLOCKED [test:pg]: VAJRA_PG_INTEGRATION=1 is not set`).
2. Non-disposable DB name (`postgresql://vajra_test:<REDACTED>@127.0.0.1:5432/vajra_prod`) -> **Exit `2`** (`BLOCKED [test:pg]: Database name "vajra_prod" does not contain "test", "ci", or "local"`).
3. Production environment (`NODE_ENV=production`) -> **Exit `2`** (`BLOCKED [test:pg]: Refusing to run disposable integration suite when NODE_ENV/APP_ENV is production`).

### Migration & `npm run test:pg` Results
Command:
```bash
VAJRA_PG_INTEGRATION=1 NODE_ENV=test APP_ENV=test \
  DATABASE_URL="postgresql://vajra_test:<REDACTED>@127.0.0.1:5432/vajra_test?schema=public" \
  npm run test:pg
```
- **Exit Code**: `0`
- **Migrations Applied**: Forward-only migrations `0003_device_heartbeats_and_nonces`, `0004_audit_log_immutability`, `0005_analytics_security_evidence_views`, `0006_user_mfa_stepup`, and `0007_heartbeat_charging_and_battery_index` applied cleanly (20 tables/views verified).
- **Test Count**: **8 passed, 0 failed across 2 suites** (`duration_ms: 3810.82`).
- **Verified Real PostgreSQL Operations**:
  1. `reports PostgreSQL backend health on readiness` — `/readyz` confirms `database: "ok"` against live PostgreSQL.
  2. `registers a user and rejects duplicate email (unique constraint)` — Argon2id credential storage + relational unique index enforcement (`409`).
  3. `persists session, enables MFA, and grants action-scoped step-up` — `DeviceSession`, AES-256-GCM encrypted TOTP secret, hashed recovery codes, and `StepUpGrant` (`ENABLE_LOST_MODE`) persisted in PostgreSQL.
  4. `enrolls a device through pending → confirm and rejects cross-user access` — Full enrollment (`EnrollmentChallenge`, `Device`, `DeviceCredential`), cross-user `404 DEVICE_NOT_FOUND` isolation, signed `DeviceHeartbeat` + `DeviceAuthNonce` persistence, replay rejection (`409 DEVICE_NONCE_REPLAYED`), and full command lifecycle (`POST /commands` -> `GET /commands/pending` -> `POST /acknowledge` -> `POST /result`) with direct SQL verification of `RemoteCommand.status = 'COMPLETED'` and `CommandResult.status = 'COMPLETED'`.
  5. `returns analytics from persisted records with PERSISTED dataSource` — Persisted `ThreatCheck` + `ThreatIndicator` aggregation via `/api/analytics/summary`.
  6. `enforces append-only AuditLog at the database layer` — PostgreSQL trigger `VAJRA_AUDIT_IMMUTABLE` rejects raw SQL `UPDATE` and `DELETE` on `"AuditLog"`, and `verifyAuditChain()` validates cryptographic hash continuity.
  7. `persists signed Android battery telemetry and enforces history rules` — Persists valid signed Android battery heartbeats, rejects out-of-range `batteryLevel` (`150`, `-1`) and invalid `charging` types without writing rows, enforces the 24-hour window and 100-reading cap in chronological order, blocks cross-user reads (`404`), and rejects Windows devices (`400 UNSUPPORTED_PLATFORM`).
  8. `server.ts rejects production without a real DATABASE_URL` — Confirms fail-closed production startup guards.

---

## 5. Browser E2E Claims & Data-Source Classification

### Audit of Prompt 0045 Claims vs Actual Behavior
1. **Real Browser & Real Server**: Confirmed. `tests/e2e/browser-e2e.test.ts` launches headless Chromium (`/ms-playwright/chromium_headless_shell-1247`) via `playwright-core` against a live HTTP server running `createVajraApiApp` and serving the production Vite bundle from `dist/`. Only external `res.cloudinary.com` background video requests are aborted so tests remain deterministic offline.
2. **Data-Source Distinction (`IN_MEMORY` vs `POSTGRESQL_PRISMA`)**:
   - When `DATABASE_URL` is unset or a `.env.example` placeholder (`npm run test:e2e:browser` with default env), `USE_PG` is `false` and the server uses `InMemoryIdentityRepository`. State survives browser reloads (`page.reload()`) within the same Node process, **not** across server restarts or database boundaries.
   - When `DATABASE_URL` points to disposable `vajra_test`, `USE_PG` is `true` and the server uses `PrismaIdentityRepository` backed by PostgreSQL `15.19`. Test 8 spins up a second independent Express + `PrismaClient` server on a new port and signs in with a fresh browser context to verify true database-boundary survival.
3. **Corrections Made to Prior E2E Claims**:
   - Previously, Test 6 enrolled via `page.evaluate(fetch(...))` with Node-generated keys, stopped at `State: QUEUED` without exercising command receipts, and never clicked `Lost Mode` or opened the MFA Step-Up modal despite its title.
   - Test 6 now completes signed command polling, acknowledgement, and `COMPLETED` receipt rendering in the drawer, **and** clicks `Lost Mode` -> `Enable Lost Mode` -> `STEP_UP_REQUIRED` (`Scope: ENABLE_LOST_MODE`) -> live TOTP verification -> `Turn Off Lost Mode` visible.
   - Test 8 now exercises the actual 3-step `Connect Device` UI wizard (`window.crypto.subtle` ECDSA P-256 keypair generation & DER signature in Chromium) and cross-server PostgreSQL survival.

### Browser E2E Test Matrix (8 Tests — Verified in Both Modes)

| Test # | Workflow | Browser UI Actions | Default Run (`IN_MEMORY`) | PostgreSQL Run (`POSTGRESQL_PRISMA`) | Persistence Boundary Proven |
|---|---|---|---|---|---|
| **1** | Owner registration, Overview load, sign-out, sign-in | Real form fills & button clicks | PASS | PASS | Session & Argon2id auth roundtrip |
| **2** | Honest empty device inventory & opt-in sample toggle | Navigation & toggle clicks | PASS | PASS | Zero fabricated devices in store |
| **3** | Accessible `Modal` & `NotificationSlideOverPanel` + `375x812` mobile overflow check | Focus trap (`Tab`/`Shift+Tab`), `Escape`, viewport resize | PASS | PASS | UI accessibility & zero horizontal overflow |
| **4** | TOTP MFA setup, 8 recovery codes, sign-out, MFA sign-in | Settings -> Security -> Enable Authenticator -> TOTP login | PASS | PASS | Encrypted TOTP secret & MFA-gated login |
| **5** | ThreatCheck restricted URL inspection & token redaction | URL input submit & indicator inspection | PASS | PASS | `access_token=[REDACTED]`, lexical limitation note |
| **6** | Windows enrollment, `REQUEST_DEVICE_STATUS` -> signed poll/ack/receipt (`COMPLETED`), `Lost Mode` -> `ENABLE_LOST_MODE` MFA step-up | Device card click, drawer actions, Recovery modal, MFA Step-Up modal | PASS | PASS | Full command receipt + action-scoped step-up unlock |
| **7** | Security Analytics summary & JSON/CSV report exports | Overview analytics & authenticated `/api/reports/export` | PASS | PASS | `Cache-Control: no-store` & exported device rows |
| **8** | 3-step Android WebCrypto wizard + second-server login check | `Connect Device` Steps 01 -> 02 (`window.crypto.subtle`) -> 03 | PASS (in-process) | PASS (cross-server DB) | Survives independent Express + `PrismaClient` restart |

---

## 6. Native Agent Build & Runtime Readiness (`GAP-WIN-01`, `GAP-AND-01`)

### Windows Service Agent (`apps/windows-agent`)
- **Command Executed**: `npm run test:windows-agent` (`node scripts/verify-windows-agent.mjs`)
- **Exit Code**: `2`
- **Observed Output**:
  `BLOCKED [test:windows-agent]: Missing prerequisite(s): Windows 10/11 host required (current platform: linux); .NET 8 SDK (dotnet CLI) not found on PATH.`
- **Environment Check**: Host OS is Linux `x64` (`Debian bookworm` container); `dotnet` CLI is not installed and official Microsoft `.NET 8` APT repository is not configured in `/etc/apt/sources.list.d/`. Furthermore, `Vajra.WindowsAgent.csproj` targets `net8.0-windows` (`Microsoft.Extensions.Hosting.WindowsServices`, DPAPI `ProtectedData`, Windows Event Log).
- **Classification**: **BLOCKED** (Requires Windows 10/11 host + .NET 8 SDK for build, xUnit suite, and Windows Service E2E). Note: Cryptographic protocol parity (ECDSA P-256 IEEE P1363-to-DER conversion, canonical JSON hashing, enrollment PoP, and Plane-2 request signing) is verified on the server contract side in `tests/prompt0016-protocol-parity.test.ts`, which is **not** claimed as a substitute for native Windows execution.

### Android Companion App (`apps/android`)
- **Command Executed**: `./apps/android/gradlew -p apps/android testDebugUnitTest assembleDebug`
- **Exit Code**: `1`
- **Observed Output**:
  `ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.`
- **Environment Check**: Neither JDK 17 (`java`) nor Android SDK Platform 34 (`ANDROID_HOME` / `sdkmanager`; `apps/android/app/build.gradle.kts` requires `compileSdk = 34`, AGP `8.5.2`, Kotlin `1.9.24`, JDK `17`) is installed in the container (Debian `bookworm` APT only carries legacy Android API 28 packages, which cannot compile `compileSdk = 34`).
- **Classification**:
  - **APK Build & JVM Unit Tests (`DeviceRequestSignerTest.kt`)**: **BLOCKED** (Requires JDK 17 + Android SDK Platform 34).
  - **Physical-Device / Emulator Runtime E2E (Hardware Keystore, QR Camera Scan, WorkManager, `BatteryManager` Telemetry)**: **BLOCKED / NOT TESTED** (Requires physical Android 8.0+ device or Android Emulator connected via `adb`).

---

## 7. Complete Verification Matrix & Final Reconciled Status

### Command Execution Summary (Prompt 0046 Final Baseline)

| Check | Exact Command | Exit Code | Result Summary | Status |
|---|---|---|---|---|
| **Lint** | `npm run lint` | `0` | `tsc --noEmit` — 0 errors | **PASS** |
| **Typecheck** | `npm run typecheck` | `0` | `tsc --noEmit` — 0 errors | **PASS** |
| **Prisma Validate** | `npm run db:validate` | `0` | `prisma/schema.prisma is valid` | **PASS** |
| **Production Build** | `npm run build` | `0` | Prisma Client generated; Vite `dist/` built cleanly (`1.30s`) | **PASS** |
| **Clean Lockfile Install** | `npm --prefix /var/tmp/vajra-npm-clean ci --legacy-peer-deps` | `0` | `added 298 packages, audited 302 packages`, `0 vulnerabilities` | **PASS** |
| **Dependency Security Audit** | `npm audit --registry https://registry.npmjs.org` | `0` | `found 0 vulnerabilities` (`bun audit`: `0 vulnerabilities`) | **PASS** |
| **Unit & API Suite** | `npm test` | `0` | **92 passed, 0 failed across 29 suites** (`12.37s`) | **PASS** |
| **Browser E2E (Default In-Memory)** | `npm run test:e2e:browser` | `0` | **8 passed, 0 failed** (`IN_MEMORY`, `11.92s`) | **PASS** |
| **Browser E2E (Disposable PostgreSQL)** | `DATABASE_URL="postgresql://vajra_test:<REDACTED>@127.0.0.1:5432/vajra_test?schema=public" npm run test:e2e:browser` | `0` | **8 passed, 0 failed** (`POSTGRESQL_PRISMA` + cross-server survival, `11.88s`) | **PASS** |
| **PostgreSQL Integration Suite** | `VAJRA_PG_INTEGRATION=1 NODE_ENV=test APP_ENV=test DATABASE_URL="postgresql://vajra_test:<REDACTED>@127.0.0.1:5432/vajra_test?schema=public" npm run test:pg` | `0` | **8 passed, 0 failed across 2 suites** (`3.81s`, 5 migrations verified) | **PASS** |
| **Windows Agent Runner** | `npm run test:windows-agent` | `2` | `BLOCKED`: Linux host lacks Windows 10/11 OS & `.NET 8 SDK` | **BLOCKED** |
| **Android Gradle Build & Unit Tests** | `./apps/android/gradlew -p apps/android testDebugUnitTest assembleDebug` | `1` | `BLOCKED`: Missing JDK 17 (`JAVA_HOME`) & Android SDK Platform 34 | **BLOCKED** |

### Reconciled Gap Status Table

| Gap ID | Area | Previous Status (0045) | Current Status (0046) | Evidence Summary |
|---|---|---|---|---|
| **GAP-AUDIT-01** | npm Lockfile & Vulnerability Audit | BLOCKED (`ENOLOCK`) | **PASS** | `/package-lock.json` generated, `npm ci --legacy-peer-deps` verified, `npm audit` = `0 vulnerabilities`. |
| **GAP-PG-01** | Live PostgreSQL Integration & Persistence | BLOCKED (No PG instance) | **PASS** | Verified against disposable loopback PostgreSQL 15.19 (`vajra_test`): `test:pg` **8/8 PASS** + `test:e2e:browser` (`POSTGRESQL_PRISMA`) **8/8 PASS**. |
| **GAP-WIN-01** | Native Windows Agent Build & Service Runtime | BLOCKED | **BLOCKED** | Requires Windows 10/11 runner + `.NET 8 SDK` (`net8.0-windows`, DPAPI, Windows Service SCM). |
| **GAP-AND-01a** | Android Companion APK Build & JVM Unit Tests | BLOCKED | **BLOCKED** | Requires JDK 17 + Android SDK Platform 34 (`ANDROID_HOME`). |
| **GAP-AND-01b** | Physical Android Device E2E (Keystore / Battery / WorkManager) | BLOCKED | **NOT TESTED** (Blocked by hardware) | Requires physical Android 8.0+ phone or `adb`-attached emulator talking to live server. |
| **GAP-AZ-01** | Azure Cloud Infrastructure Provisioning & Deploy | NOT IMPLEMENTED | **NOT IMPLEMENTED** | Target cloud deployment remains intentionally unprovisioned per scope rules. |

### Next Highest-Priority Unresolved Integration Gap
- **Next Priority**: **`GAP-WIN-01` & `GAP-AND-01a/b` — Native Endpoint Agent Toolchain & Hardware/VM Execution**.
- **Smallest Safe Next Action**: Run `npm run test:windows-agent` on a Windows 10/11 CI runner or workstation with `.NET 8 SDK` installed, and run `./apps/android/gradlew -p apps/android testDebugUnitTest assembleDebug` in an environment provisioned with JDK 17 and Android SDK Platform 34, followed by enrolling one Windows VM and one Android test device against the PostgreSQL-backed VAJRA server.
