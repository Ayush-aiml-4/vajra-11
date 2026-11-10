# VAJRA — Implementation & Release-Acceptance Roadmap (Prompt 0051)

Synchronized with the source-grounded Prompt 0051 baseline (`docs/quality/final-gap-closure-0051.md`).

---

## Completed & Verified in Repository (`IMPLEMENTED` / `VERIFIED IN THIS RUN`)

| ID | Milestone | Evidence |
| :---: | :--- | :--- |
| **A1** | Fail-closed CSP (`frame-ancestors 'none'` + `X-Frame-Options: DENY` default, validated `CSP_FRAME_ANCESTORS`, `'unsafe-eval'` removed) | `src/server/app.ts`, `packages/config/src/index.ts`, `tests/prompt0051-security-gap-closure.test.ts` |
| **A2** | Trusted-proxy gating (`isTrustedProxyRequest`) for `X-Forwarded-Proto/Ssl/Host/For` cookie, CSRF & rate-limit security | `src/server/auth/middleware.ts`, `src/server/auth/routes.ts`, `tests/prompt0050-login-fix.test.ts`, `tests/prompt0051-security-gap-closure.test.ts` |
| **A3** | Strict platform command capability enforcement (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`), receipt-gated execution, and terminal-state immutability | `src/server/notifications/routes.ts`, `src/App.tsx`, `tests/prompt0051-security-gap-closure.test.ts` |
| **A4** | Truthful server-side account Lost Mode (`SERVER_ACCOUNT_STATE`, no fake `ONLINE` status or OS-lock claim) | `src/server/notifications/routes.ts`, `src/server/events/engine.ts`, `src/App.tsx` |
| **A5** | Revocation/decommission pending-command cancellation & fresh-keypair re-enrollment (`AndroidKeystoreIdentity.rotateKey()`) | `src/server/devices/routes.ts`, `apps/android/.../AndroidKeystoreIdentity.kt`, `EnrollmentActivity.kt` |
| **A6** | Production `/api/demo/*` hard-disable (`404 DEMO_DISABLED`) & fail-closed DB/origin startup | `server.ts`, `src/server/notifications/routes.ts` |
| **A7** | Documentation & API route synchronization (`README.md`, `docs/api/endpoints.md`, `docs/security/production-checklist.md`) | Prompt 0051 Phase 6 |
| **A8** | Automated Web/API/Browser Verification (`113/113` unit/API tests, `9/9` Chromium E2E tests, `0` npm audit vulns, offline Azure preflight PASS) | Prompt 0051 Phase 5 |

---

## Remaining External Environment & Hardware Closure Gates (`BLOCKED` on Current Linux Container)

| ID | Gate | Required Runner / Prerequisite | Acceptance Proof Command |
| :---: | :--- | :--- | :--- |
| **G1** | Disposable PostgreSQL Integration Suite (9 tests: migrations `0003`–`0007`, `AuditLog` immutability trigger, replay & isolation) | Host/CI runner with disposable PostgreSQL 16 (`127.0.0.1:5432`) | `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://..." npm run test:pg` + `./infrastructure/scripts/backup-postgres.sh` |
| **G2** | Windows Agent Native Build, Protocol Tests & Live SCM Service Verification | Windows 10 22H2+ / Windows 11 host with `.NET 8 SDK` | `npm run test:windows-agent` + enroll -> confirm -> heartbeat -> `REQUEST_DEVICE_STATUS` receipt -> revoke -> re-enroll |
| **G3** | Android Companion APK Build, Unit Tests & Physical Device Verification | Host with `JDK 17` + `Android SDK Platform 34` + Android 10–15 device | `npm run test:android-agent` + enroll -> heartbeat -> `RING_DEVICE` visible foreground notification -> revoke -> `rotateKey()` re-enroll |
| **G4** | Controlled Staging Cloud Provisioning & TLS Cutover | Operator-approved Azure subscription + `az` CLI + Bicep compiler | `az bicep build --file infrastructure/azure/main.bicep` + staging slot `/api/health` & `/api/ready` over HTTPS |
