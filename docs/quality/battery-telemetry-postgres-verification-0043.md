# VAJRA — Battery Telemetry PostgreSQL Verification (Prompt 0043)

**Date:** 2026-10-23  
**Scope:** Extend `tests/postgres-integration.test.ts` so battery telemetry is executed against disposable PostgreSQL `vajra_test`. No Azure deploy. No frontend changes. No production database was contacted. This is not a real Android device end-to-end run.

**Overall:** `npm run test:pg` **PASS**.  
**Counts:** 8 tests, 2 suites, 8 pass, 0 fail, 0 skipped. Duration `3880.99 ms`. Exit code `0`.

The new case is `persists signed Android battery telemetry and enforces history rules` (`509.75 ms`). The previous seven cases from Prompt 0042 still pass.

---

## 1. What changed

No application behavior, schema, migration, or safety guard was changed.

`tests/postgres-integration.test.ts` reuses `registerOwner`, `enrollConfirmedDevice`, `signedDeviceHeaders`, and `postSignedHeartbeat`. Enrollment still uses Ed25519 proof-of-possession. Heartbeats still use Plane-2 canonical signatures, fresh timestamps, and unique nonces. The history limit is the existing constant `BATTERY_HISTORY_RESULT_LIMIT` (`100` in `src/server/notifications/routes.ts`).

Rows that must be older than "now" are inserted through `PrismaIdentityRepository.createDeviceHeartbeat` with an explicit `receivedAt`. The heartbeat HTTP route always stamps `receivedAt` at ingest time, so a signed request cannot create a 26-hour-old row. Invalid, omitted, and the newest valid reading still go through the signed HTTP route. The test deletes only `DeviceHeartbeat` rows for the Android and Windows devices it enrolled. Audit log rows are left in place because that table is append-only.

---

## 2. Database target

Same disposable cluster as Prompt 0042:

| Check | Result |
| :--- | :--- |
| Engine | PostgreSQL 15.18 (Debian 15.18-0+deb12u1) |
| Host / port | `127.0.0.1:5432` only (`listen_addresses = '127.0.0.1'`) |
| Database | `vajra_test` |
| Role used by tests | `vajra_test` (not a superuser) |
| Other databases on the cluster | `postgres`, `template0`, `template1` |
| TCP auth | `scram-sha-256` |
| `npm run test:pg` guard | Printed `Safety check passed (host=127.0.0.1:5432, db=vajra_test)` |

`npx prisma migrate deploy` inside `test:pg` reported `No pending migrations to apply.` Migrations `0003` through `0007` were already applied. No database was dropped or reset.

The test password is a local random secret and is not recorded here.

---

## 3. `npm run test:pg`

```bash
VAJRA_PG_INTEGRATION=1 NODE_ENV=test APP_ENV=test \
DATABASE_URL='postgresql://vajra_test:<redacted>@127.0.0.1:5432/vajra_test?schema=public' \
npm run test:pg
```

Exit code **0**.

```text
# tests 8
# suites 2
# pass 8
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 3880.991465
```

| # | Test | PostgreSQL | Status | Duration |
| :--- | :--- | :---: | :---: | ---: |
| 1 | `reports PostgreSQL backend health on readiness` | Yes | **PASS** | 35.44 ms |
| 2 | `registers a user and rejects duplicate email (unique constraint)` | Yes | **PASS** | 157.82 ms |
| 3 | `persists session, enables MFA, and grants action-scoped step-up` | Yes | **PASS** | 132.05 ms |
| 4 | `enrolls a device through pending → confirm and rejects cross-user access` | Yes | **PASS** | 347.79 ms |
| 5 | `returns analytics from persisted records with PERSISTED dataSource` | Yes | **PASS** | 101.38 ms |
| 6 | `enforces append-only AuditLog at the database layer` | Yes | **PASS** | 56.67 ms |
| 7 | `persists signed Android battery telemetry and enforces history rules` | Yes | **PASS** | 509.75 ms |
| 8 | `server.ts rejects production without a real DATABASE_URL` | Source check | **PASS** | 0.73 ms |

### Battery case (test 7), all against `vajra_test`

| Requirement | Result |
| :--- | :--- |
| Signed Android heartbeat with `batteryLevel` and `charging` is stored | **PASS.** `POST` returned `200`. Response and `DeviceHeartbeat` row both had `batteryLevel = 64` and `charging = true` (`agentVersion = 0.1.0-battery`). |
| Owner `GET /api/devices/:id/battery-history` returns persisted values in chronological order | **PASS.** `200`, `hasTelemetry: true`, `currentLevel: 64`, `charging: true`. Timestamps are non-decreasing. The last reading is `64` / `true` and matches the persisted `receivedAt`. |
| Records older than 24 hours are excluded by the server `since` bound | **PASS.** A row at 26 hours (`batteryLevel` 17) stayed in the table and was absent from `readings`. Every returned timestamp was within 24 hours of the request. |
| Configured maximum result count | **PASS.** Route limit is `BATTERY_HISTORY_RESULT_LIMIT` (`100`). The test asserted that constant and received exactly 100 readings. An in-window overflow row older than those 100 remained stored and was not listed. |
| Invalid battery level and non-boolean charging are rejected and not stored | **PASS.** `batteryLevel` `150` and `-1` returned `400 INVALID_BATTERY_LEVEL`. `charging: "yes"` returned `400 INVALID_CHARGING_STATE`. Heartbeat count did not increase. No row with `batteryLevel` outside 0–100 or `batteryLevel = 80` was inserted. |
| Another user cannot read the history | **PASS.** `404 DEVICE_NOT_FOUND`. |
| Non-Android device | **PASS.** Enrolled Windows device returned `400 UNSUPPORTED_PLATFORM`. |
| Omitted battery telemetry stays valid and is not fabricated | **PASS.** Signed heartbeat without `batteryLevel` or `charging` returned `200` with both fields `null`. History stayed `hasTelemetry: false` and `readings: []` until real battery values existed. |

Not claimed: a physical or emulated Android companion sending these heartbeats. The signer is the existing Node test client.

---

## 4. In-memory coverage, kept separate

`npm test` does not set `VAJRA_PG_INTEGRATION`, so the live PostgreSQL describe is not executed. TAP marks that suite:

`ok ... PostgreSQL integration ... # SKIP BLOCKED: Missing prerequisite — Set VAJRA_PG_INTEGRATION=1 and a disposable PostgreSQL DATABASE_URL`

The Node summary line still printed `# skipped 0` because the skipped describe does not register its inner tests. Those eight PostgreSQL cases are **not** inside the 87.

| Command | Result |
| :--- | :--- |
| `npm test` | **PASS.** 87 pass / 0 fail / 28 suites. Duration `7475.31 ms`. Exit `0`. Includes in-memory `tests/battery-telemetry.test.ts` (11/11) and the source-level production `DATABASE_URL` guard. Does **not** include the live PostgreSQL battery case. |
| `npm run lint` (`tsc --noEmit`) | **PASS.** Exit `0`. |
| `npm run db:validate` | **PASS.** `prisma/schema.prisma` is valid. Exit `0`. |
| `npm run build` | **PASS.** `prisma generate` and `vite build` exited `0` (`1.32s`). |
| `npm audit --registry https://registry.npmjs.org` | **PASS.** `found 0 vulnerabilities`. Exit `0`. |

In-memory battery tests still use `InMemoryIdentityRepository`. They are not PostgreSQL results.

---

## 5. Result matrix

| Item | Result |
| :--- | :--- |
| Safety guards unchanged | **PASS** (same `scripts/verify-pg.mjs` checks; run targeted `vajra_test` on loopback) |
| Migrations | **PASS** (none pending; no reset) |
| `npm run test:pg` including battery telemetry | **PASS** (8/8) |
| `npm test` | **PASS** (87/87, live PostgreSQL suite skipped) |
| `npm run lint` | **PASS** |
| `npm run build` | **PASS** |
| `npm run db:validate` | **PASS** |
| `npm audit` | **PASS** (0 vulnerabilities) |
| Real Android device E2E | **NOT TESTED** |
| Azure deploy / unrelated features | **Not done** |
