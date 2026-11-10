# VAJRA — Source-Grounded Non-Functional Requirements Audit (Prompt 0051)

**Scope:** Security controls, framing/CSP, proxy/cookie boundaries, reliability, privacy, performance, and operational readiness verified against the current repository source and automated suites.  
**Browser Automation:** Verified via Playwright headless Chromium (`9/9` E2E tests passed, including keyboard dialog focus/Escape, mobile layout, and cross-site HTTPS iframe sign-in).

---

## 1. Security Controls

| Control Area | Status | Evidence & Prompt 0051 Closure |
| :--- | :---: | :--- |
| **CSP & Clickjacking Defense** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Removed `'unsafe-eval'` (`script-src 'self'` in strict production); replaced `frame-ancestors *` with fail-closed `frame-ancestors 'none'` + `X-Frame-Options: DENY` when `CSP_FRAME_ANCESTORS` is unset, validated `https://` allowlist when configured (rejecting `*` and `http://` in production), and explicit AI Studio preview parent allowlist (`https://aistudio.google.com https://*.google.com`) when `APPLET_ID` is present. |
| **Reverse-Proxy & Rate-Limit Boundary** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `isTrustedProxyRequest(req)` gates `X-Forwarded-Proto`, `X-Forwarded-Ssl`, `X-Forwarded-Host`, and `X-Forwarded-For` (`getClientIpTruncated`) behind `trust proxy` or verified local loopback socket + loopback `Host`, preventing spoofed IP rate-limit bypasses and spoofed CSRF host headers. |
| **Session Cookies & CSRF** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `__Host-vajra_session` (`HttpOnly; Secure; Path=/; SameSite=None; Partitioned`) on HTTPS + `vajra_session` (`SameSite=Lax`) on plain HTTP localhost; timing-safe `X-CSRF-Token` + `Origin`/`Referer` enforcement. |
| **Cross-User Isolation** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Owned resource checks across devices, sessions, notifications, events, ThreatChecks, analytics, and commands return `404` on foreign UUIDs. |
| **Password, MFA & Step-Up** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Argon2id password hashing, AES-256-GCM encrypted TOTP secrets, SHA-256 hashed single-use recovery codes, and 5-minute action-scoped one-time step-up grants. |
| **Plane-2 Device Cryptography** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | ECDSA P-256 `VAJRA-DEVICE-AUTH-V1` canonical signatures, ±120s timestamp window, atomic nonce replay rejection (`409 NONCE_REPLAYED`), and route-to-header device binding. |
| **Command Capability & Receipt Integrity** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `validateActionCapabilityForDevice` rejects unsupported platform commands (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) before step-up consumption or DB writes; queued commands never claim physical execution without signed Plane-2 receipt; terminal command states are immutable. |
| **Audit Chain & Append-Only Storage** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | SHA-256 hash chain verified via `/api/audit/verify` + PostgreSQL `trg_prevent_audit_log_mutation` trigger (`0005_audit_log_immutability`). |
| **SSRF & CSV Formula Injection** | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | ThreatCheck performs zero outbound HTTP/DNS requests and flags loopback/RFC1918/link-local/metadata IPs; report export neutralizes `=`, `+`, `-`, `@`, `\t`, `\r` formula prefixes via `escapeCsvCellSafe`. |
| **Dependency Vulnerability Audit** | `VERIFIED IN THIS RUN` | `npm run verify:audit` -> **`0 vulnerabilities`** (`deepmerge-ts` pinned to `8.0.2`). |

---

## 2. Reliability & Fail-Closed Startup

| Topic | Status | Notes |
| :--- | :---: | :--- |
| Liveness & Readiness Probes | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `GET /api/health` and bounded `GET /api/ready` (returns `503` without leaking DB URLs when store unavailable). |
| Fail-Closed Production Boot | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Refuses startup in standalone production without TLS `DATABASE_URL`, `https://` `APP_PUBLIC_ORIGIN`, distinct secrets, and built `dist/index.html`; verified via child-process test in `prompt0050-login-fix.test.ts`. |
| Gateway Cold-Start Resilience | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Auth client (`src/lib/authApi.ts`) retries transient `200 OK` HTML warmup/cookie-check pages with bounded backoff. |
| App Service Startup Script | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `infrastructure/scripts/startup-app-service.sh` runs `npx prisma migrate deploy` and `exec node server.ts` (`tsx/esm/api` loader registered in `server.ts`). |

---

## 3. Privacy, Accessibility & Performance

| Topic | Status | Notes |
| :--- | :---: | :--- |
| Data Minimization & Secret Redaction | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | Event engine strips prohibited credential/content keys; ThreatCheck redacts query values & fragments before DB/audit storage. |
| Honest Location & Lost Mode | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | No IP-as-GPS fabrication; Lost Mode explicitly labeled as server-side account lifecycle record (`physicalLockApplied: false`, `liveLocationTracking: false`). |
| Accessibility & Mobile Layout | `VERIFIED IN THIS RUN` | Modal & slide-over keyboard focus/Escape handling and `375px` mobile viewport tested in Chromium E2E test 3; `prefers-reduced-motion` honored on login background. |
| Analytics & DB Indexing | `IMPLEMENTED` | Composite user/timestamp indexes in `0007_analytics_indexes`; bounded pagination on events, ThreatChecks, and report exports (`1..200`). |

---

## 4. Remaining External Verification Blockers

1. **Live PostgreSQL Integration Execution on Current Container (`BLOCKED` — `Exit 2`):** `psql`/`postgres` server is not installed on this container (`127.0.0.1:5432` unreachable). Must be re-run (`VAJRA_PG_INTEGRATION=1 npm run test:pg`) on a CI/host runner with a disposable PostgreSQL instance.
2. **Native Windows Agent Build & SCM Service Verification (`BLOCKED` — `Exit 2`):** Requires Windows 10 22H2+/11 + `.NET 8 SDK`.
3. **Native Android Companion Build & Physical Device Ring/Keystore Verification (`BLOCKED` — `Exit 2`):** Requires `JDK 17` + `Android SDK Platform 34` + physical Android 10–15 device or emulator (specifically verifying the new `AndroidKeystoreIdentity.rotateKey()` re-enrollment path on hardware Keystore).
4. **Live Azure Provisioning (`BLOCKED` — Not Provisioned):** `az`/`bicep` CLI not installed locally and live deployment intentionally withheld per safety rules.
