# VAJRA — Prompt 0050: Sign-In Failure Root-Cause Diagnosis & Repair Report

**Date:** 2026-11-01  
**Phase:** Authentication & Session Persistence Defect Diagnosis and Surgical Repair (Prompt 0050)  
**Scope:** End-to-end root-cause reproduction, cookie/CSRF reverse-proxy hardening, frontend session-confirmation & error-display repair, and regression coverage across `IN_MEMORY` and `POSTGRESQL_PRISMA` backends. No UI redesign, no security weakening, and no feature expansion.

---

## 1. Executive Summary & Root Cause

### Observed User-Visible Symptom
When clicking **"Sign In to VAJRA"** on the login screen:
1. The submit button briefly changed to **"Signing in..."**.
2. The application remained on the login screen instead of opening the console.
3. The password field became empty (`""`).
4. Zero error banners or toast messages were visible.

### Confirmed Multi-Layer Root Cause
Inspection of the live container reverse-proxy configuration (`/etc/nginx/nginx.conf`), Express authentication/session middleware (`src/server/auth/middleware.ts`), and React authentication state machine (`src/App.tsx`)—confirmed by both direct HTTP proxy reproduction and an unmocked headless Chromium cross-site HTTPS `<iframe>` reproduction—identified **four interacting defects**:

1. **Internal HTTP Reverse-Proxy Header Overwrite Caused Non-Secure `SameSite=Lax` Cookie Issuance (`src/server/auth/middleware.ts`):**
   - In the hosted preview / reverse-proxy topology, external TLS terminates upstream before reaching a container sidecar Nginx (`listen 8080;` over plain HTTP), which proxies to `http://localhost:3000` with:
     - `Host: localhost:3000`
     - `X-Forwarded-Host: <public-https-host>`
     - `X-Forwarded-Proto: http` (because Nginx's local `$scheme` on port `8080` is `http`, overwriting the outer `https` hop)
     - `Origin: https://<public-https-host>`
   - Because `NODE_ENV=development` and `TRUST_PROXY=false` in the preview container, `isSecureRequest(req)` saw `req.secure === false` and `X-Forwarded-Proto === 'http'`, returning `false`.
   - `setSessionCookie` therefore emitted `Set-Cookie: vajra_session=[REDACTED]; Path=/; HttpOnly; SameSite=Lax; Max-Age=900` (without `Secure`, `SameSite=None`, or `Partitioned`).
   - Even when `isSecureRequest(req)` evaluated to `true`, `__Host-vajra_session` lacked the CHIPS `Partitioned` attribute required by Chromium when VAJRA is rendered inside a cross-site HTTPS preview `<iframe>` with third-party cookie restrictions active.

2. **Frontend Cleared Password & Switched to Console Before Confirming Cookie Persistence, Triggering Silent `401` Eviction (`src/App.tsx`):**
   - `handleLoginSubmit` in `src/App.tsx` trusted the `200 OK` JSON body of `POST /api/auth/login` immediately without verifying that the browser stored and returned the session cookie on `GET /api/auth/me`.
   - It immediately executed `setPasswordInput('')` (emptying the password field) and `setCurrentUser(data.user)`, mounting the dashboard effects (`fetchAnalyticsSummary`, `fetchThreatCheckHistory`, `fetchActiveSessions`, etc.).
   - Because Chromium had rejected the `SameSite=Lax` cookie inside the cross-site HTTPS `<iframe>`, every dashboard `GET /api/*` request arrived without a `Cookie` header and returned **`401 UNAUTHENTICATED`**.
   - `fetchAnalyticsSummary()` caught `res.status === 401` and called `handleSessionExpired()`, which called `setCurrentUser(null)` and `showToast('Your session has expired...', 'info')`—**without setting `authError`**.
   - Because `<Toast>` is rendered only inside the authenticated console branch (`currentUser !== null`) and NOT inside the `!currentUser` login gate, unmounting the console destroyed the toast immediately, leaving the user back on the login screen with an empty password field and zero error messages.

3. **Loopback Reverse-Proxy Host Mismatch Broke Authenticated State-Changing Requests (`403 CSRF_ORIGIN_MISMATCH`) (`src/server/auth/middleware.ts`):**
   - `requireAuthenticatedUser` compared `Origin` (`https://<public-https-host>`) strictly against `req.headers.host` (`localhost:3000`) while ignoring `X-Forwarded-Host`.
   - Consequently, `POST /api/auth/logout`, `POST /api/auth/mfa/setup`, device enrollment initiation, and ThreatCheck mutations behind the container sidecar proxy failed with `403 CSRF_ORIGIN_MISMATCH`.

4. **Rotated CSRF Header Desynchronization on `GET /api/auth/me` (`src/server/auth/routes.ts`):**
   - When an authenticated session crossed the 7.5-minute idle rotation threshold (`SESSION_ROTATION_THRESHOLD_MS`) on `GET /api/auth/me`, `createSessionResolutionMiddleware` set `X-Vajra-Csrf-Token` to the rotated token, and the `/auth/me` handler then generated a second `freshPair` and updated `csrfTokenHash` in persistence without updating the `X-Vajra-Csrf-Token` response header.

---

## 2. Before vs. After Evidence (Secrets Redacted)

### Original Failing Sequence (Reproduced Pre-Fix)
Reproduced both against the live port `3000` server and in headless Chromium (`--test-third-party-cookie-phaseout`) with parent origin `https://studio-parent.other-site.example` embedding `<iframe src="https://vajra-preview.app-site.example">` behind an HTTP sidecar reverse proxy (`Host: localhost:<port>`, `X-Forwarded-Host: vajra-preview.app-site.example`, `X-Forwarded-Proto: http`):

1. `GET /api/auth/me` -> `401 Unauthorized`
2. User enters valid email + password and clicks **"Sign In to VAJRA"**:
   - Request: `POST /api/auth/login` (`Origin: https://vajra-preview.app-site.example`)
   - Response: `200 OK`, `{ "authenticated": true, "mfaRequired": false, "csrfToken": "[REDACTED]", "user": { ... } }`
   - Failing `Set-Cookie`:
     ```text
     vajra_session=[REDACTED]; Path=/; HttpOnly; SameSite=Lax; Max-Age=900
     ```
   - Browser rejects `SameSite=Lax` non-`Secure` cookie in the cross-site HTTPS iframe.
3. Frontend clears `passwordInput` (`""`), sets `currentUser`, and fires dashboard requests:
   - `GET /api/devices?includeDecommissioned=true` -> `401`
   - `GET /api/audit` -> `401`
   - `GET /api/activity` -> `401`
   - `GET /api/notifications` -> `401`
   - `GET /api/analytics/summary` -> `401` -> triggers `handleSessionExpired()` -> `setCurrentUser(null)`
   - `GET /api/threatcheck/history?limit=15&offset=0` -> `401`
   - `GET /api/auth/sessions` -> `401`
4. Resulting DOM state:
   - `stillOnLoginScreen: true`
   - `submitButtonText: "Sign In to VAJRA"`
   - `passwordFieldValue: ""`
   - `visibleAlertCount: 0`
5. Additionally, calling `POST /api/auth/logout` with valid session cookie + `X-CSRF-Token` behind the proxy returned:
   - `403 Forbidden` `{ "error": { "code": "CSRF_ORIGIN_MISMATCH", "message": "Cross-origin state-changing request rejected." } }`

### Corrected Sequence (Verified Post-Fix)
Under the exact same cross-site HTTPS `<iframe>` + HTTP reverse-proxy topology:

1. `POST /api/auth/login` -> `200 OK`
   - Corrected `Set-Cookie`:
     ```text
     __Host-vajra_session=[REDACTED]; Path=/; HttpOnly; SameSite=None; Max-Age=900; Secure; Partitioned
     ```
2. Frontend calls `confirmSessionAfterAuth` (`GET /api/auth/me`) **before** clearing `passwordInput` or mounting the authenticated console:
   - `GET /api/auth/me` -> `200 OK` (`Cookie: __Host-vajra_session=[REDACTED]` sent by Chromium from its partitioned cookie jar).
3. Frontend clears `passwordInput`, increments `authEpochRef`, sets `csrfToken` + `currentUser`, and renders the **Overview (`Protection Index`)** dashboard with `200 OK` across all dashboard API calls.
4. Navigating to **Devices** and reloading the iframe restores the session via `GET /api/auth/me` -> `200 OK`.
5. Clicking **Settings -> Sign Out** executes `POST /api/auth/logout` -> `200 OK`, clears both `vajra_session` and `__Host-vajra_session` (`Partitioned; Max-Age=0`), revokes the database session, and returns cleanly to the login screen.

---

## 3. Files Changed & Rationale

| File | Summary of Changes & Security Rationale |
| :--- | :--- |
| `src/server/auth/middleware.ts` | 1. Enhanced `isSecureRequest(req)` to detect outer HTTPS termination via `req.secure`, multi-hop `X-Forwarded-Proto` (`https`), `X-Forwarded-Ssl: on`, browser `Origin`/`Referer` `https:` scheme (explicitly preserving `false` for `http://localhost` / `http://127.0.0.1`), existing `__Host-vajra_session` cookie on `GET` requests (where `Referrer-Policy: no-referrer` omits `Referer`), or `X-Forwarded-Host` matching a configured `https://` `APP_PUBLIC_ORIGIN`/`APP_URL`.<br>2. Added `Partitioned` (CHIPS) alongside `HttpOnly; SameSite=None; Secure; Path=/` on `__Host-vajra_session` in `setSessionCookie` and `clearSessionCookies` when `secure` is `true`, keeping `vajra_session` (`HttpOnly; SameSite=Lax; Path=/`) for plain local HTTP.<br>3. Updated `requireAuthenticatedUser` CSRF origin verification to accept `X-Forwarded-Host` when `trust proxy` is enabled OR when the request arrives from a loopback socket (`127.0.0.1`/`::1`) with a loopback `Host` header (`localhost:<port>`), while still rejecting cross-origin requests (`403 CSRF_ORIGIN_MISMATCH`), spoofed non-loopback `X-Forwarded-Host` (`403 CSRF_ORIGIN_MISMATCH`), and production `APP_PUBLIC_ORIGIN` mismatches. |
| `src/server/auth/routes.ts` | Synchronized `X-Vajra-Csrf-Token` response header with `freshPair.rawCsrfToken` in `GET /api/auth/me` whenever idle session rotation set `X-Vajra-Csrf-Token` earlier in the request pipeline. |
| `src/App.tsx` | 1. Added synchronous `authSubmittingRef` lock in `handleLoginSubmit` and `handleRegisterSubmit` to block duplicate concurrent submissions before React state re-renders.<br>2. Added `confirmSessionAfterAuth` (`GET /api/auth/me`) after `200`/`201` auth responses **before** clearing `passwordInput` or setting `currentUser`; surfaces an explicit `#vajra-auth-error` (`role="alert"`) message if the browser blocks cookies instead of silently resetting the form.<br>3. Added safe `.json().catch(() => null)` parsing and `formatAuthErrorResponse` distinguishing `400` validation errors, `401` invalid credentials / MFA code, `409` conflict, `423` lockout, `429` rate limit, `502`/`503`/`504` service unavailability (including HTML gateway pages), `500` unexpected server errors, and network failures—preserving `passwordInput` on failed password sign-in.<br>4. Added monotonic `authEpochRef` guards across `fetchCurrentSession`, `fetchAnalyticsSummary`, `fetchThreatCheckHistory`, and `fetchActiveSessions` so stale `401` responses cannot clobber a freshly established session.<br>5. Rendered a minimal `"Verifying session..."` state while `authChecking && !currentUser` and populated `authError` inside `handleSessionExpired` so session expiry is always visible on the login screen.<br>6. Updated `handleLogout` to retry once with a fresh `/api/auth/me` CSRF token on `403` and cleanly reset client state. |
| `tests/prompt0050-login-fix.test.ts` | New unit + API regression suite verifying local HTTP cookies, reverse-proxy HTTPS `__Host-vajra_session; Partitioned` issuance, idle session rotation without `Origin`/`Referer`, CSRF `X-Forwarded-Host` acceptance vs. cross-origin & non-loopback spoofing rejection, MFA challenge/TOTP login, step-up enforcement, and logout revocation. |
| `tests/e2e/browser-e2e.test.ts` | Added Test `9`: real headless Chromium E2E test reproducing the cross-site HTTPS `<iframe>` + HTTP reverse-proxy topology (`--test-third-party-cookie-phaseout`) across both `IN_MEMORY` and `POSTGRESQL_PRISMA` backends, verifying invalid credentials, `503` HTML / `500` / network errors, duplicate submit prevention, cookie-blocked detection, valid sign-in, reload session restoration, and sign-out. |
| `tests/postgres-integration.test.ts` | Added Prompt 0050 PostgreSQL integration test verifying reverse-proxy HTTPS `__Host-vajra_session; Partitioned` persistence, `/api/auth/me` restoration, MFA setup/verify + TOTP challenge, and logout session revocation against a real disposable PostgreSQL 15 database. |

---

## 4. Verification & Regression Test Results

All checks were executed against the current workspace with zero secrets or connection strings printed:

| Command | Mode / Target | Result | Details |
| :--- | :--- | :--- | :--- |
| `npm run lint` | TypeScript (`tsc --noEmit`) | **PASS** (`Exit 0`) | Zero syntax or type errors |
| `npm run typecheck` | TypeScript (`tsc --noEmit`) | **PASS** (`Exit 0`) | Zero type errors across frontend, server, shared packages, and tests |
| `npm run db:validate` | Prisma Schema | **PASS** (`Exit 0`) | `prisma/schema.prisma` validated cleanly |
| `npm run verify:audit` | npm Lockfile Security Audit | **PASS** (`Exit 0`) | `found 0 vulnerabilities` |
| `npx tsx --test tests/auth-foundation.test.ts tests/prompt0050-login-fix.test.ts` | Auth, Proxy Cookie & `node server.ts` Regression | **PASS** (`Exit 0`) | **12 / 12 tests** across **6 suites** passed (`0` failed) |
| `npm test` | Full Unit, API & Security Suite | **PASS** (`Exit 0`) | **110 / 110 tests** across **33 suites** passed (`0` failed) |
| `DATABASE_URL="" npm run test:e2e:browser` | Headless Chromium E2E (`IN_MEMORY`) | **PASS** (`Exit 0`) | **9 / 9 E2E tests** passed, including Test `9` cross-site HTTPS iframe login, `200 OK` `warmup.html` auto-retry, `cookie_check.html` reload recovery, reload restoration, and logout |
| `VAJRA_PG_INTEGRATION=1 npm run test:pg` | Disposable Local PostgreSQL 15 (`127.0.0.1:5432/vajra_test`) | **PASS** (`Exit 0`) | All 5 Prisma migrations applied; **11 / 11 tests** across **2 suites** passed (`0` failed); cluster destroyed on exit |
| `npm run test:e2e:browser` (with disposable `vajra_test`) | Headless Chromium E2E (`POSTGRESQL_PRISMA`) | **PASS** (`Exit 0`) | **9 / 9 E2E tests** passed against real PostgreSQL, including Test `8` cross-server persistence and Test `9` cross-site HTTPS iframe sign-in |
| `npm run build` | Prisma Generate + Vite Production Bundle | **PASS** (`Exit 0`) | `dist/index.html` and hashed client assets built cleanly |

---

## 5. Follow-Up Diagnosis & Fix: `"An unexpected server response was received during sign-in. Please try again."`

### Observed Follow-Up Symptom
After an extended container idle period (~3.5 hours), clicking **"Sign In to VAJRA"** displayed:
> `"An unexpected server response was received during sign-in. Please try again."`

### Confirmed Forensic Root Cause
1. **Container Cold-Start `HTTP 200 OK` `warmup.html` Interception (`/etc/nginx/nginx.conf`):**
   - Container process timestamps (`ps aux`) showed the sandbox woke from sleep at `15:10 UTC`, the user submitted sign-in at `15:11:34 UTC` (`20:41:34 IST`), and the Node server finished booting at `15:12 UTC`.
   - In `/etc/nginx/nginx.conf`, `proxy_intercept_errors on; error_page 502 503 504 = /warmup.html;` rewrites upstream `502 Bad Gateway` during startup into **`HTTP 200 OK` `text/html` (`/var/www/assets/warmup.html`, `<title>Starting Server...</title>`)**.
   - Because HTTP status was `200 OK` (not `502`/`503`), `fetch('/api/auth/login')` saw `res.ok === true`, `.json().catch(() => null)` returned `null`, and `!data?.user` fell into the generic `"An unexpected server response..."` branch.
2. **Idle Preview Gateway Auth Cookie Expiry (`302` -> `/__cookie_check.html` -> `200 OK` HTML):**
   - When the outer preview gateway cookie expires while a tab sits idle, `/etc/nginx/user_auth_verification.lua` redirects `POST /api/auth/login` (`302`) to `/__cookie_check.html?return_url=...`, which `fetch()` follows as `GET` (`res.redirected === true`), returning `200 OK` HTML (`__SECURE-aistudio_auth_flow_may_set_cookies`).
3. **Shared / Deployed Full-Stack Start Command (`package.json` & `server.ts`):**
   - `package.json` previously defined `"start": "tsx server.ts"` and `"preview": "vite preview"`, whereas full-stack deployment expects `"start": "node server.ts"`. Running `node server.ts` directly on Node 22 failed on TypeScript `enum` strip-only mode, and `NODE_ENV=production` inside `APPLET_ID` preview containers without `DATABASE_URL` rejected startup.

### Fixes Applied
- **`src/App.tsx` (`performResilientAuthFetch` & `triggerGatewaySessionRefresh`):**
  - Automatically detects `200 OK` `warmup.html` (`Starting Server` / `warmup_start_time`) across `/api/auth/me`, `/api/auth/login`, and `/api/auth/register` and retries up to 4 times with backoff (`800ms`, `1200ms`, `1600ms`, `2000ms`) so cold-start sign-in completes seamlessly once `server.ts` comes online.
  - Detects gateway auth-bridge responses (`res.redirected` / `__cookie_check.html` / `applet-auth-bridge`), preserves typed `emailInput` (never password) in `sessionStorage`, and triggers a guarded one-time page reload (max once per 30s) plus a `visibilitychange` wake check after >60s tab sleep so the host gateway re-mints its auth cookie automatically.
- **`package.json`, `server.ts`, & `src/server/auth/middleware.ts`:**
  - Updated `"start"` and `"preview"` in `package.json` to `"node server.ts"`.
  - Registered `tsx/esm/api` in `server.ts` when invoked via `node server.ts` so TypeScript `enum` modules load cleanly on Node 22.
  - Scoped strict fail-closed production mode (`isProductionEnv()`) to `APP_ENV=production` or `NODE_ENV=production` outside preview sandboxes (`!process.env.APPLET_ID`), preserving all production fail-closed checks while allowing `ais-pre` shared preview containers without `DATABASE_URL` to run the full Express + `/api/*` backend cleanly.

---

## 6. Remaining Environment / Platform Blockers

No blockers remain for web authentication, cold-start warmup recovery, gateway cookie refresh, session persistence, CSRF protection, MFA/step-up, or PostgreSQL persistence. Unchanged host-toolchain blockers outside the web sign-in flow remain truthfully reported:

- **Native Windows Agent (`npm run test:windows-agent` -> `Exit 2` BLOCKED):** Host container is Linux `x86_64` without the `.NET 8` SDK (`dotnet`) or Windows Service Control Manager.
- **Native Android Companion (`npm run test:android-agent` -> `Exit 2` BLOCKED):** Host container does not have JDK 17+ (`java`) or Android SDK 34 (`ANDROID_HOME`) installed.
- **Cloud Provisioning:** Azure Bicep templates remain unprovisioned by design per workspace non-deployment rules.
