# Local PostgreSQL integration (Prompt 0021)

## Prerequisites

- PostgreSQL 14+ (verified with **16.15**)
- Node.js 20+ with project dependencies installed via `npm ci --legacy-peer-deps`
- A **disposable** database (never production)

## Create a test database

```bash
sudo -u postgres psql -c "CREATE USER vajra_test WITH PASSWORD 'replace-me' CREATEDB;"
sudo -u postgres psql -c "CREATE DATABASE vajra_test OWNER vajra_test;"
sudo -u postgres psql -d vajra_test -c "GRANT ALL ON SCHEMA public TO vajra_test;"
```

## Environment

Copy `.env.test.example` to an untracked local file (never commit real credentials):

```bash
export NODE_ENV='test'
export APP_ENV='test'
export DATABASE_URL='postgresql://vajra_test:replace-with-local-test-password@127.0.0.1:5432/vajra_test?schema=public'
export VAJRA_PG_INTEGRATION=1
# Optional for API process:
# export TOTP_ENCRYPTION_KEY='a-long-random-test-only-secret-min-32-chars'
# export SESSION_SECRET='a-distinct-random-test-only-secret-min-32-chars'
```

Do not commit credentials. Prefer a local ignored `.env.test.local`.

### Disposable Test-Database Safety Guard (`scripts/verify-pg.mjs`)

`npm run test:pg` invokes `scripts/verify-pg.mjs`, which enforces before running migrations or tests:
- `NODE_ENV` and `APP_ENV` must not be `production`.
- `VAJRA_PG_INTEGRATION=1` must be explicitly set.
- `DATABASE_URL` (or `VAJRA_TEST_DATABASE_URL`) must not be a placeholder (`replace-me`, `username:password@`, `changeme`, `example.com`).
- The database name in `DATABASE_URL` **must** contain `test` (for example `vajra_test`) so integration tests can never target a production database.
- The database host must be loopback (`127.0.0.1`, `localhost`, `::1`) unless `VAJRA_ALLOW_REMOTE_TEST_DB=1` is explicitly set.
- If any prerequisite is missing or PostgreSQL is unreachable, `npm run test:pg` exits with code `2` and prints `BLOCKED [test:pg]: <reason>` without printing any credentials.

## Migrate and generate

```bash
npx prisma generate
npx prisma migrate deploy
npx prisma migrate status
```

## Run tests

```bash
# Unit / in-memory suite (default)
npm test

# Real PostgreSQL integration suite
VAJRA_PG_INTEGRATION=1 DATABASE_URL="$DATABASE_URL" npm run test:pg
```

## Production fail-closed

With `NODE_ENV=production` or `APP_ENV=production`, the server:

- Requires a non-placeholder `DATABASE_URL`
- Connects to PostgreSQL at startup
- **Does not** fall back to in-memory identity storage

## Verified objects (after migrate deploy)

Tables include User, UserCredential, DeviceSession, Device, DeviceCredential, EnrollmentChallenge,
DeviceAuthNonce, DeviceHeartbeat, RemoteCommand, CommandResult, AuditLog, SecurityEvent,
Notification, ThreatCheck, ThreatIndicator, RiskAssessment, PasskeyCredential.

Views: `vw_device_security_posture`, `vw_command_audit_history`  
Functions: `fn_prevent_audit_log_mutation`, `fn_record_command_execution_result`  
Trigger: `trg_prevent_audit_log_mutation` on `AuditLog`
