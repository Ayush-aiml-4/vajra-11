# VAJRA — Verification Environment & E2E Readiness Report (Prompt 0036)

**Date:** 2026-10-11  
**Workspace:** `/tmp/vajra-durable` (linked to `/app/applet`)  
**Status:** Regression gates **PASS** | Live PostgreSQL integration **BLOCKED / NOT RUN** | Automated Browser E2E **BLOCKED / NOT RUN** | Real Windows Agent E2E **BLOCKED / NOT RUN**

This report records the actual runtime environment, prerequisite guardrails, executed commands, and reproducible workflows for each verification layer. **No unavailable workflow (PostgreSQL integration, automated browser E2E, or real Windows-agent E2E) is claimed as passed.**

---

## 1. Environment Inventory

| Component | Status | Observed Details |
| :--- | :---: | :--- |
| **OS & Kernel** | Present (Linux) | `Debian GNU/Linux 12 (bookworm)` — `Linux localhost 4.19.0-gvisor #1 SMP x86_64 GNU/Linux` |
| **Architecture** | `x86_64` (`linux x64`) | Not a Windows host (`process.platform === 'linux'`) |
| **Node.js** | **Available** | `v22.23.2` (`/usr/local/bin/node`) |
| **npm** | **Available** | `10.9.8` (`/usr/local/bin/npm`) |
| **.NET 8 SDK / Runtime (`dotnet`)** | **MISSING (BLOCKED)** | `which dotnet` not found; no .NET SDK or runtime installed |
| **Java (`java` / `javac`)** | **MISSING (BLOCKED)** | Neither `java` nor `javac` is installed on `PATH` |
| **Android SDK / `adb`** | **MISSING (BLOCKED)** | `adb` not found; `ANDROID_HOME` and `ANDROID_SDK_ROOT` are unset |
| **PostgreSQL Client / Server** | **MISSING (BLOCKED)** | `psql`, `pg_isready`, and `postgres` are not installed; no local PostgreSQL listener on `:5432` |
| **Docker** | **MISSING (BLOCKED)** | `which docker` not found |
| **Browser Binaries** | **MISSING (BLOCKED)** | `chromium`, `chromium-browser`, `google-chrome`, `firefox`, and `webkit` are absent on `PATH`; `~/.cache/ms-playwright` is absent |
| **Playwright CLI** | CLI only (`1.64.0`) | Global CLI resolves `Version 1.64.0`, but no browser binaries or `playwright.config.ts` exist |
| **Disk Space** | **Available** | `/` and `/tmp`: `378G` total, `~377G`–`378G` free (`1%` used) |
| **Writable Project Paths** | **Available** | `/app/applet` (`drwxr-xr-x root:root`) and `/tmp/vajra-durable` (`lrwxrwxrwx -> /app/applet`) |

---

## 2. Verification Layer Distinction & Summary Verdict

VAJRA strictly distinguishes between simulated/in-memory checks and real infrastructure or endpoint execution:

| Verification Layer | Execution Mechanism | Uses Real PostgreSQL? | Uses Real Browser? | Uses Real Windows Agent Process? | Prompt 0036 Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Static TypeScript, Build, Schema & Audit Gates** | `tsc --noEmit`, `vite build`, `prisma validate`, `npm audit` | No | No | No | **PASS** |
| **Unit Tests & In-Memory API Tests** | `tsx --test tests/*.test.ts` against `InMemoryIdentityRepository` | No (in-memory only) | No (Node `http` + source checks) | No (Node crypto transcript tests only) | **PASS** (76 pass, 0 fail, 1 PG suite explicitly `skipped` with `BLOCKED` reason) |
| **Database Integration Tests (`PrismaIdentityRepository`)** | `npm run test:pg` (`scripts/verify-pg.mjs` -> `tests/postgres-integration.test.ts`) | **Yes (Required)** | No | No | **BLOCKED / NOT RUN** (No PostgreSQL server in container) |
| **Automated Browser E2E Tests** | `npm run test:e2e:browser` (`scripts/verify-browser-e2e.mjs`) | Optional / Configurable | **Yes (Required)** | No | **BLOCKED / NOT RUN** (No browser binaries or Playwright suite installed) |
| **Windows Agent Build & `Vajra.ProtocolParity` xUnit** | `npm run test:windows-agent` (`scripts/verify-windows-agent.mjs`) | No | No | **.NET 8 Windows build (`net8.0-windows`)** | **BLOCKED / NOT RUN** (Linux host; `.NET 8 SDK` missing) |
| **Real Windows Agent End-to-End Workflow** | `Vajra.WindowsAgent` against Express + PostgreSQL | **Yes (Required)** | Yes (Owner console confirm) | **Yes (`Vajra.WindowsAgent` process)** | **BLOCKED / NOT RUN** (Requires Windows 10 22H2+/11 + .NET 8 + PostgreSQL) |

> **Honesty Rule Enforced:** In `tests/postgres-integration.test.ts`, when `VAJRA_PG_INTEGRATION=1` and a live PostgreSQL `DATABASE_URL` are not present, the suite is marked with Node test runner `{ skip: 'BLOCKED: Missing prerequisite...' }` instead of `assert.ok(true)`. It is never counted as a passing test.

---

## 3. Commands Actually Executed & Exit Codes

| Command | Exit Code | Layer | Actual Result Summary |
| :--- | :---: | :--- | :--- |
| `npm run lint` | `0` | TypeScript static check | `tsc --noEmit` completed with 0 errors |
| `npm test` | `0` | Unit & in-memory API tests | **76 pass / 0 fail / 1 skipped** (`PostgreSQL integration` suite marked `skipped` with `BLOCKED` reason; 27 suites total) |
| `npm run build` | `0` | Prisma client + Vite production bundle | Prisma Client `v6.19.3` generated; Vite client bundle emitted to `dist/` |
| `npm run db:validate` | `0` | Prisma schema validation | `The schema at prisma/schema.prisma is valid` (validated with non-secret placeholder URL) |
| `DATABASE_URL="postgresql://placeholder:placeholder@127.0.0.1:5432/vajra_validate_only?schema=public" npx prisma validate` | `0` | Direct Prisma CLI validation | `The schema at prisma/schema.prisma is valid` |
| `npm audit --registry https://registry.npmjs.org` (`npm run verify:audit`) | `0` | Dependency vulnerability scan | `found 0 vulnerabilities` |
| `npm run test:pg` (without `VAJRA_PG_INTEGRATION=1`) | `2` | PostgreSQL prerequisite gate | `BLOCKED [test:pg]: Missing prerequisite: VAJRA_PG_INTEGRATION=1 is not set.` |
| `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://vajra_user:localpass@127.0.0.1:5432/vajra_prod" npm run test:pg` | `2` | Disposable DB safety check | `BLOCKED [test:pg]: Safety check failed: Disposable test database name must contain "test" (found "vajra_prod").` |
| `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://vajra_test:localpass@127.0.0.1:5432/vajra_test" npm run test:pg` | `2` | PostgreSQL reachability gate | `BLOCKED [test:pg]: Missing prerequisite: PostgreSQL server is not reachable at 127.0.0.1:5432 (db="vajra_test").` |
| `npm run test:e2e:browser` | `2` | Browser E2E prerequisite gate | `BLOCKED [test:e2e:browser]: Missing prerequisite(s): No browser binaries found on PATH...` |
| `npm run test:windows-agent` | `2` | Windows agent prerequisite gate | `BLOCKED [test:windows-agent]: Missing prerequisite(s): Windows 10 22H2+ / Windows 11 host required (current platform: linux x64); .NET 8 SDK (dotnet CLI) not found on PATH.` |

---

## 4. Scripts & Documentation Added or Updated

| File | Change Summary |
| :--- | :--- |
| `scripts/verify-prisma-validate.mjs` | Runs `npx prisma validate` using a non-secret syntax-only placeholder URL when `DATABASE_URL` is unset so validation never leaks or requires live credentials. |
| `scripts/verify-pg.mjs` | Enforces non-production environment, `VAJRA_PG_INTEGRATION=1`, non-placeholder URL, disposable `*test*` database name, loopback host check, and TCP reachability before running `prisma migrate deploy` and `tests/postgres-integration.test.ts`. Exits `2` (`BLOCKED`) when prerequisites are missing. |
| `scripts/verify-browser-e2e.mjs` | Checks for local browser binaries (`chromium`/`google-chrome` or `~/.cache/ms-playwright`) and `playwright.config.ts`; exits `2` (`BLOCKED`) when missing. |
| `scripts/verify-windows-agent.mjs` | Checks for `win32` host OS and `dotnet` CLI on `PATH`; exits `2` (`BLOCKED`) on non-Windows hosts or when `.NET 8 SDK` is missing. On Windows with `.NET 8`, runs `dotnet restore`, `dotnet build -c Release`, and `dotnet test tests/Vajra.ProtocolParity -c Release`. |
| `scripts/README.md` | Documents all verification scripts, exit codes, and the disposable database safety guard. |
| `.env.test.example` | Provides a placeholder-only test environment template (`NODE_ENV="test"`, `APP_ENV="test"`, `VAJRA_PG_INTEGRATION="1"`, disposable `vajra_test` database URL). |
| `tests/postgres-integration.test.ts` | Replaced the fake-pass `assert.ok(true)` skip stub with Node test runner `{ skip: 'BLOCKED: Missing prerequisite...' }` so skipped PostgreSQL tests are never reported as passed. |
| `package.json` | Added `db:validate`, `verify:audit`, `test:e2e:browser`, `test:windows-agent`, and wired `test:pg` to `node scripts/verify-pg.mjs`. |
| `docs/deployment/postgresql-local.md` | Documented `.env.test.example` and the `scripts/verify-pg.mjs` disposable database safety guard. |
| `docs/deployment/environment-variables.md` | Documented test-only configuration requirements and isolation rules. |

---

## 5. Safe Test-Only Environment Configuration

Test configurations must use `.env.test.example` as a template and obey the following security invariants:

1. **Never target production databases:** `scripts/verify-pg.mjs` refuses to run if `NODE_ENV=production` or `APP_ENV=production`, if the host is non-loopback (unless `VAJRA_ALLOW_REMOTE_TEST_DB=1`), or if the database name does not contain `test` (e.g., `vajra_test`).
2. **Production startup remains fail-closed:** `server.ts` and `packages/config/src/index.ts` continue to reject missing/placeholder `DATABASE_URL`, short/placeholder `SESSION_SECRET` or `TOTP_ENCRYPTION_KEY`, and identical session/TOTP secrets when `NODE_ENV=production` or `APP_ENV=production`.
3. **Zero credential leakage:** Verification scripts never print `DATABASE_URL`, `SESSION_SECRET`, or `TOTP_ENCRYPTION_KEY` to stdout, stderr, or markdown reports.
4. **Isolated test records:** `tests/postgres-integration.test.ts` scopes test accounts and devices with random per-run suffixes (`pg.owner.a.<hex>@vajra.test`) and verifies cross-user isolation (`403`/`404`).

### Reproducing PostgreSQL Integration Tests on a Machine with PostgreSQL 14+

```bash
# 1. Create a disposable local test database (never use a production instance)
sudo -u postgres psql -c "CREATE USER vajra_test WITH PASSWORD '<LOCAL_TEST_ONLY_PASSWORD>' CREATEDB;"
sudo -u postgres psql -c "CREATE DATABASE vajra_test OWNER vajra_test;"
sudo -u postgres psql -d vajra_test -c "GRANT ALL ON SCHEMA public TO vajra_test;"

# 2. Run the guarded PostgreSQL verification script (applies migrations + runs suite)
VAJRA_PG_INTEGRATION=1 \
DATABASE_URL="postgresql://vajra_test:<LOCAL_TEST_ONLY_PASSWORD>@127.0.0.1:5432/vajra_test?schema=public" \
npm run test:pg
```

---

## 6. Browser Test Readiness & Manual Smoke-Test Procedure

### Automated Browser E2E Status: **BLOCKED / NOT RUN**
- **Blocker:** This container has no browser binaries (`chromium`, `google-chrome`, `firefox`, `webkit`) and no `~/.cache/ms-playwright` browser installation. Installing multi-hundred-megabyte browser packages and system graphics libraries is not justified in this sandbox.
- **How to run on a suitable developer workstation:**
  1. Install Playwright browsers on the workstation: `npx playwright install chromium`
  2. Start the VAJRA server in test/dev mode: `npm run dev` (listening on `http://127.0.0.1:3000`)
  3. Once a `playwright.config.ts` and E2E spec suite are configured on the workstation, run: `npm run test:e2e:browser`

### Manual Browser Smoke-Test Checklist (Reproducible against `npm run dev` on `:3000`)

1. **Registration & Login:**
   - Open `http://127.0.0.1:3000`.
   - Register a new owner account (`Create account` mode) with display name, email, and a passphrase of at least 10 characters.
   - Verify automatic sign-in to the Overview command center, then sign out and sign back in with the same credentials.
2. **Multi-Factor Authentication (TOTP & Recovery Codes):**
   - Open Account Security / MFA setup, initiate TOTP setup (`POST /api/auth/mfa/setup`), and scan or inspect the Base32 secret.
   - Enter a valid 6-digit TOTP code (`POST /api/auth/mfa/verify`) and verify that 8 single-use recovery codes are displayed once.
   - Sign out, sign back in with password + TOTP code (or a single-use recovery code), and confirm login succeeds.
3. **Empty Inventory Honesty & Opt-In Sample Preview:**
   - On a fresh account with zero enrolled devices, verify the device inventory shows the honest empty state (**0 enrolled devices**) and does **not** present `ASUS TUF F16` or `Android Phone` sample cards as real enrolled devices.
   - Toggle the opt-in **Sample Device Preview** control and confirm sample cards are clearly badged as preview/sample data and separated from real enrolled inventory.
4. **Unsupported Platform Actions & Step-Up Gating:**
   - Enroll a test device (or inspect device action controls) and verify that platform-unsupported actions (such as GPS location or ringing on a Windows PC, or unimplemented remote actions) are explicitly labeled as unsupported and cannot be executed as fake simulated device actions.
   - Trigger a sensitive lifecycle action (`Revoke Device`, `Mark Compromised`, or `Enable/Disable Lost Mode`) and verify the server returns `403 STEP_UP_REQUIRED` and the UI opens the MFA Step-Up verification modal before executing the action.
5. **Notifications & Activity Timeline:**
   - Open the Notifications / Activity view, filter by severity or category, mark an unread security notification as read, and verify the unread counter decrements and audit/activity items use calm, human-readable copy without internal cryptographic jargon.
6. **ThreatCheck URL Inspection & History:**
   - Navigate to **ThreatCheck**, submit `http://127.0.0.1:8080/admin?access_token=SECRET123#frag`, and verify:
     - The verdict (`HIGH RISK`), numeric risk score, and **Restricted Destination Boundary Flagged** banner render.
     - Query secrets and URL fragments are redacted (`access_token=[REDACTED]`) in both the live result and **ThreatCheck History**.
     - The **Explainable Threat Indicators** list and explicit **Limitations note** (lexical analysis only; never claims a URL is 100% safe) are visible.
7. **Security Analytics & Report Export (JSON / CSV):**
   - In the Overview / Analytics section (`05 · SECURITY ANALYTICS & REPORT EXPORT`), click **Refresh Analytics** and verify persisted counts update.
   - Click **Export JSON** and **Export CSV** and verify both downloads succeed with `Cache-Control: no-store` and formula-safe CSV cells.
8. **Mobile Navigation & Keyboard-Accessible Dialogs:**
   - Resize the viewport to mobile width (`375x812`), open the mobile navigation drawer/menu, and navigate across sections without horizontal overflow.
   - Open a modal dialog (e.g., **Enroll New Device** or **MFA Step-Up**), navigate interactive controls using `Tab` / `Shift+Tab`, and press `Escape` to verify keyboard dismissal and focus restoration.

---

## 7. Windows-Agent Verification Readiness & Repeatable 10-Step Workflow

### Current Host Status: **BLOCKED / NOT RUN**
- **Blocker:** Current host is `Linux x86_64` (`Debian 12`) without `.NET 8 SDK` (`dotnet`) or PostgreSQL. `apps/windows-agent/Vajra.WindowsAgent.csproj` targets `net8.0-windows` (`UseWindowsService=true`) and uses Windows DPAPI (`ProtectedData` / `DataProtectionScope.LocalMachine`) and `EventLogReader`.
- Running `npm run test:windows-agent` on this host exits with code `2` (`BLOCKED [test:windows-agent]`).

### Repeatable 10-Step Workflow on a Supported Windows Host (Windows 10 22H2+ / Windows 11)

**Prerequisites on the Windows machine:**
- Windows 10 22H2+ or Windows 11 (`win-x64` or `win-arm64`)
- .NET 8 SDK (`dotnet --version` >= `8.0.x`)
- Node.js 20/22+ and npm
- Local PostgreSQL 14+ running on `127.0.0.1:5432`

#### Step 1: Start a disposable PostgreSQL database and apply migrations
```powershell
psql -U postgres -h 127.0.0.1 -c "CREATE USER vajra_test WITH PASSWORD '<LOCAL_TEST_PASSWORD>' CREATEDB;"
psql -U postgres -h 127.0.0.1 -c "CREATE DATABASE vajra_test OWNER vajra_test;"
psql -U postgres -h 127.0.0.1 -d vajra_test -c "GRANT ALL ON SCHEMA public TO vajra_test;"

$env:NODE_ENV = "test"
$env:APP_ENV = "test"
$env:VAJRA_PG_INTEGRATION = "1"
$env:DATABASE_URL = "postgresql://vajra_test:<LOCAL_TEST_PASSWORD>@127.0.0.1:5432/vajra_test?schema=public"
npx prisma generate
npx prisma migrate deploy
npm run test:pg
```

#### Step 2: Start the VAJRA API server with test-only configuration
```powershell
$env:NODE_ENV = "development"
$env:APP_ENV = "development"
$env:PORT = "3000"
$env:DATABASE_URL = "postgresql://vajra_test:<LOCAL_TEST_PASSWORD>@127.0.0.1:5432/vajra_test?schema=public"
$env:SESSION_SECRET = "<GENERATE_32_BYTE_HEX_TEST_SESSION_SECRET>"
$env:TOTP_ENCRYPTION_KEY = "<GENERATE_DISTINCT_32_BYTE_HEX_TEST_TOTP_KEY>"
$env:VAJRA_ENABLE_DEMO_ENDPOINTS = "false"
npm run dev
```

#### Step 3: Build the Windows agent, run `Vajra.ProtocolParity` tests, register an owner, and initiate Windows enrollment
In a second PowerShell terminal:
```powershell
# Verify Windows agent build and ECDSA DER / canonical JSON protocol parity tests
npm run test:windows-agent
```
In the web console (`http://127.0.0.1:3000`):
1. Register an owner account and enable TOTP MFA.
2. Open **Enroll New Device**, select platform **WINDOWS**, enter a device name (e.g. `Win11-Test-PC`), and submit (`POST /api/devices/enrollment/initiate` -> `201 Created`).
3. Record the one-time `enrollmentToken`, `deviceId`, and `challengeNonce`.
4. On the Windows host, submit the agent's ECDSA P-256 public key and proof-of-possession signature:
```powershell
cd apps/windows-agent
$env:VAJRA_SERVER_BASE_URL = "http://127.0.0.1:3000"
$env:VAJRA_DATA_DIRECTORY = "$env:TEMP\vajra-agent-test"
dotnet run -c Release -- enroll --token <ENROLLMENT_TOKEN> --device-id <DEVICE_UUID> --challenge-nonce <CHALLENGE_NONCE_HEX>
```
Verify the enrollment submission returns `200 OK` and that the device remains in `ENROLLMENT_PENDING` until the owner confirms.

#### Step 4: Confirm enrollment in the owner console
- In the web console (`http://127.0.0.1:3000`), verify the public key fingerprint and click **Confirm Enrollment** (`POST /api/devices/<DEVICE_UUID>/enrollment/confirm` -> `200 OK`).
- Verify `Device.lifecycleState` transitions to `TRUSTED` and `DeviceCredential.status` transitions to `ACTIVE`.

#### Step 5: Start the actual Windows agent
```powershell
cd apps/windows-agent
$env:VAJRA_SERVER_BASE_URL = "http://127.0.0.1:3000"
$env:VAJRA_DATA_DIRECTORY = "$env:TEMP\vajra-agent-test"
dotnet run -c Release
```

#### Step 6: Verify a signed heartbeat and persisted device status
- Observe `HeartbeatWorker` enviar `POST /api/devices/<DEVICE_UUID>/heartbeat` signed with `ECDSA_P256` (`X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`).
- Verify `200 OK` / `201 Created` on the server, `Device.connectivityStatus = 'ONLINE'`, `Device.lastHeartbeatAt` populated in PostgreSQL, and a `DeviceHeartbeat` row persisted.

#### Step 7: Issue `REQUEST_DEVICE_STATUS`
- As the authenticated owner in the web console (or via `POST /api/devices/<DEVICE_UUID>/commands` with valid session cookie and `X-CSRF-Token`), issue `{"actionType":"REQUEST_DEVICE_STATUS","payload":{}}`.
- Verify response `201 Created` with `status: "QUEUED"`.

#### Step 8: Verify the actual agent acknowledges and executes the command
- Observe `CommandPollerWorker` poll `GET /api/devices/<DEVICE_UUID>/commands/pending` (`200 OK`), send `POST /api/devices/<DEVICE_UUID>/commands/<COMMAND_UUID>/ack` (`200 OK`, `status: "ACKNOWLEDGED"`), execute the allowlisted local status inspection (`CommandCapabilityMatrix.IsExecutableOnWindows("REQUEST_DEVICE_STATUS") == true`), and submit `POST /api/devices/<DEVICE_UUID>/commands/<COMMAND_UUID>/result` with `status: "COMPLETED"`.

#### Step 9: Verify the signed result receipt is persisted and visible in activity/audit history
- Verify in PostgreSQL (`RemoteCommand` and `CommandResult` tables) and in the web console Activity / Audit view (`GET /api/audit` and `GET /api/devices/<DEVICE_UUID>/commands`) that `RemoteCommand.status = 'COMPLETED'`, the signed `CommandResult` receipt is stored, and the hash-chained `AuditLog` verification remains `valid: true`.

#### Step 10: Verify unauthorized cross-user access and unsupported commands are rejected
- Register a second user account (`user-b@vajra.test`) and request `GET /api/devices/<DEVICE_UUID>` or `POST /api/devices/<DEVICE_UUID>/commands`; verify the server rejects cross-user access with `404` / `403`.
- Verify that replay of a previously used `X-Vajra-Nonce` is rejected with `409 DEVICE_NONCE_REPLAYED`.
- Verify that unsupported Windows commands (`REQUEST_LOCATION`, `RING_DEVICE`, `DISPLAY_RECOVERY_MESSAGE`) are rejected and never executed as arbitrary shell commands.

---

## 8. Remaining Blockers & Next Actions

1. **PostgreSQL Integration Suite (`npm run test:pg`):**
   - **Blocker:** No PostgreSQL server or client binaries (`postgres`, `psql`, `pg_isready`) exist in this Linux container.
   - **Next Action:** Run `npm run test:pg` on a developer machine or CI runner with a disposable local PostgreSQL 14+ instance (`vajra_test`).
2. **Automated Browser E2E Suite (`npm run test:e2e:browser`):**
   - **Blocker:** No browser binaries (`chromium`/`google-chrome` or `~/.cache/ms-playwright`) or `playwright.config.ts` exist in this container.
   - **Next Action:** Run the manual smoke-test checklist in Section 6 against the live dev server (`http://127.0.0.1:3000`), or provision Playwright Chromium on a full workstation.
3. **Real Windows Agent Verification (`npm run test:windows-agent` + 10-step E2E):**
   - **Blocker:** Current host is Linux `x86_64` without `.NET 8 SDK`.
   - **Next Action:** Execute `npm run test:windows-agent` and the 10-step workflow in Section 7 on a Windows 10 22H2+ or Windows 11 host with `.NET 8 SDK` and local PostgreSQL.
