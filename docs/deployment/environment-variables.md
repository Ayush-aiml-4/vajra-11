# VAJRA — Environment Variables Reference

**Status:** Prompt 0013  
**Source of truth for names:** `packages/config/src/index.ts`, `server.ts`, `src/server/auth/*`, Prisma

Secrets must never be logged or committed. Use Azure App Settings / Key Vault references in production.

| Variable | Required (prod) | Purpose |
| :--- | :---: | :--- |
| `NODE_ENV` | Yes | `production` / `development` / `test` |
| `APP_ENV` | Yes | Aligns with `NODE_ENV` for production gates |
| `PORT` | Yes (platform) | Listen port; App Service injects automatically |
| `DATABASE_URL` | Yes | PostgreSQL URL; production rejects placeholders |
| `SESSION_SECRET` | Yes | ≥32 char non-placeholder; session integrity material |
| `TOTP_ENCRYPTION_KEY` | Yes | ≥32 char; AES-GCM for TOTP secrets; distinct from session |
| `TRUST_PROXY` | Recommended | `true` behind Azure TLS termination |
| `APP_PUBLIC_ORIGIN` | Recommended (`Required` when `REQUIRE_PUBLIC_ORIGIN=true`) | Canonical `https://` origin in production (`http://` rejected in production) |
| `REQUIRE_PUBLIC_ORIGIN` | Recommended | `true` in production to fail closed if `APP_PUBLIC_ORIGIN` is omitted |
| `DATABASE_SSL_REQUIRED` | Recommended | `true` in production to fail closed unless `DATABASE_URL` includes `sslmode=require`/`verify-ca`/`verify-full` |
| `VAJRA_ENABLE_DEMO_ENDPOINTS` | Recommended (`false`) | Keep `false` in production and test verification; demo routes are disabled in production |
| `APP_URL` | Optional | Alternate name accepted for public origin |
| `SESSION_TTL_SECONDS` | Optional | Idle session policy (60–86400) |
| `REQUIRE_MFA` | Optional | Policy flag (default true) |
| `VAJRA_SEED_*` | No (dev only) | Seed script only |
| `VITE_LOGIN_BG_VIDEO_URL` | Optional | Build-time login video URL |
| `GEMINI_API_KEY` | Optional | Only if AI features enabled |

## Production validation behavior

See `.env.production.example` for the hardened placeholder template. `assertProductionConfigOrThrow()` / `validateRuntimeConfig()` and `server.ts` reject:

- Missing or placeholder `DATABASE_URL`
- Missing TLS `sslmode` when `DATABASE_SSL_REQUIRED=true`
- Short (`< 32` chars) or placeholder secrets
- Identical `SESSION_SECRET` and `TOTP_ENCRYPTION_KEY`
- Non-HTTPS (`http://`) `APP_PUBLIC_ORIGIN` in production, or missing `APP_PUBLIC_ORIGIN` when `REQUIRE_PUBLIC_ORIGIN=true`
- Missing compiled frontend bundle (`dist/index.html`) when `server.ts` starts in production mode

## Local development

1. `cp .env.example .env`
2. Optionally set a real local `DATABASE_URL` (for example via `infrastructure/docker/docker-compose.postgres.yml`); otherwise the server uses in-memory identity **only when not in production**.

## Disposable test-only configuration (Prompt 0036 / Prompt 0048)

1. See `.env.test.example` for placeholder-only test environment variables (`NODE_ENV="test"`, `APP_ENV="test"`, `VAJRA_PG_INTEGRATION="1"`).
2. Integration tests (`npm run test:pg`) require a non-placeholder loopback PostgreSQL URL whose database name contains `test` (e.g. `vajra_test`) and refuse to run when `NODE_ENV=production` or `APP_ENV=production`.
3. Keep `VAJRA_ENABLE_DEMO_ENDPOINTS="false"` during verification and keep test users, devices, and nonces isolated per test run.
