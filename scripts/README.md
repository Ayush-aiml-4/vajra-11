# VAJRA Verification Scripts (`scripts/`)

**Status:** Prompt 0036 — Reproducible Verification & Prerequisite Guardrails

These scripts allow developers to run each verification layer independently while ensuring that missing prerequisites produce an explicit `BLOCKED` exit (exit code `2`) rather than a false pass, and that integration tests never run against a production database.

## Scripts Overview

| NPM Script | Underlying Command | Layer | Behavior on Missing Prerequisite |
| :--- | :--- | :--- | :--- |
| `npm run lint` | `tsc --noEmit` | Static TypeScript verification | Fails (`1`) on type error |
| `npm test` / `npm run test:unit` | `tsx --test tests/*.test.ts` | Unit + in-memory API tests | Marks live PG suite as `skipped` (`BLOCKED` reason); never converts to a pass |
| `npm run build` | `prisma generate && vite build` | Production client bundle build | Fails (`1`) on build error |
| `npm run db:validate` | `node scripts/verify-prisma-validate.mjs` | Prisma schema validation | Uses non-secret placeholder URL if `DATABASE_URL` is unset |
| `npm run verify:audit` | `npm audit --registry https://registry.npmjs.org` | Dependency vulnerability audit | Fails (`1`) on vulnerable packages |
| `npm run test:pg` | `node scripts/verify-pg.mjs` | Live PostgreSQL integration (`PrismaIdentityRepository`) | Exits `2` (`BLOCKED [test:pg]`) if `VAJRA_PG_INTEGRATION!=1`, DB URL is missing/placeholder/non-test, or PostgreSQL is unreachable |
| `npm run test:e2e:browser` | `node scripts/verify-browser-e2e.mjs` | Browser E2E readiness gate | Exits `2` (`BLOCKED [test:e2e:browser]`) if browser binaries or Playwright E2E config are absent |
| `npm run test:windows-agent` | `node scripts/verify-windows-agent.mjs` | Windows agent build & `Vajra.ProtocolParity` | Exits `2` (`BLOCKED [test:windows-agent]`) if host is not `win32` or `.NET 8 SDK` (`dotnet`) is missing |
| `npm run test:android-agent` | `node scripts/verify-android-agent.mjs` | Android companion JUnit + debug APK build | Exits `2` (`BLOCKED [test:android-agent]`) if JDK 17+ or Android SDK Platform 34 (`ANDROID_HOME`) is missing |

## Disposable Database Safety Guard (`scripts/verify-pg.mjs`)

Before running `prisma migrate deploy` and `tests/postgres-integration.test.ts`, `scripts/verify-pg.mjs` verifies:
1. `NODE_ENV` and `APP_ENV` are not `"production"`.
2. `VAJRA_PG_INTEGRATION` is explicitly set to `"1"`.
3. `DATABASE_URL` (or `VAJRA_TEST_DATABASE_URL`) is non-empty and not a placeholder (`username:password@`, `replace-me`, `changeme`, `example.com`).
4. The target database name contains `"test"` (e.g., `vajra_test`).
5. The target host is loopback (`127.0.0.1`, `localhost`, `::1`) unless `VAJRA_ALLOW_REMOTE_TEST_DB=1` is set.
6. The target PostgreSQL TCP port is reachable.
7. Connection strings and credentials are never printed to stdout/stderr.
