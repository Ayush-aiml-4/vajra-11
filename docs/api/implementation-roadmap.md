# VAJRA — Implementation & Release-Acceptance Roadmap (Prompt 0051)

> Canonical copy synchronized with `docs/quality/implementation-roadmap.md` and `docs/quality/final-gap-closure-0051.md`.

All in-repository web, Express API, security header/CSP, trusted-proxy, CSRF, MFA/step-up, platform command capability, truthful Lost Mode, revocation cleanup, Android Keystore re-enrollment key-rotation (`rotateKey()`), App Service startup, and documentation tasks are **`IMPLEMENTED`** and **`VERIFIED IN THIS RUN`** (`113/113` unit/API tests, `9/9` headless Chromium E2E tests, `0` npm audit vulnerabilities, Prisma schema valid, production build clean, offline Azure preflight PASS).

### Remaining External Hardware & Infrastructure Gates (`BLOCKED` in Current Container)

1. **G1 — Disposable PostgreSQL Integration Run:** Execute `VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://..." npm run test:pg` and `backup-postgres.sh` / `restore-postgres.sh` against a live disposable PostgreSQL 16 instance.
2. **G2 — Windows `.NET 8` Native Verification:** Execute `npm run test:windows-agent` and live SCM service enrollment/heartbeat/`REQUEST_DEVICE_STATUS`/revocation on a Windows 10/11 `.NET 8 SDK` runner.
3. **G3 — Android Companion Native & Device Verification:** Execute `npm run test:android-agent` and physical Android device Keystore enrollment, `RING_DEVICE` foreground notification, revocation, and `rotateKey()` re-enrollment with `JDK 17` + `Android SDK Platform 34`.
4. **G4 — Controlled Azure Staging Deployment:** Compile `infrastructure/azure/main.bicep` with `az bicep build` and provision a staging App Service + PostgreSQL Flexible Server + Key Vault under operator approval.
