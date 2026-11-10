# Device integration report — Prompt 0028

## Environment
- Working copy: `/tmp/vajra-durable`
- Node checks: lint PASS, **77** unit tests PASS, build PASS, audit 0
- PostgreSQL: not available this session → integration **BLOCKED**
- .NET / live Windows agent process: **BLOCKED** (toolchain/host)

## Code changes (evidence-backed)

### Inventory honesty
- Default `unifiedDevices` lists **only** `enrolledDevices` from `GET /api/devices`.
- Empty list no longer auto-injects `MOCK_DEVICES` as if they were real.
- Opt-in **Show sample preview** section labels samples explicitly; not selectable as managed devices.
- Fetch failures set `devicesError` + Retry; no silent sample fallback.

### Demo isolation
- `POST /api/demo/events` returns **404 `DEMO_DISABLED`** in production (`NODE_ENV` / `APP_ENV`) or when `VAJRA_ENABLE_DEMO_ENDPOINTS=false`.

### Automated tests added
- `tests/prompt0028-inventory-demo.test.ts` (4 tests) — inventory honesty + demo gate source checks.

## Live Windows agent E2E
**NOT RUN / BLOCKED** — no claim of enrollment, heartbeat, or `REQUEST_DEVICE_STATUS` receipt in this session.

## Next steps for real agent proof
1. Start PostgreSQL disposable DB; `npx prisma migrate deploy`; `VAJRA_PG_INTEGRATION=1 npm run test:pg`
2. `NODE_ENV=development` API with `DATABASE_URL` set
3. On a Windows host: build agent, enroll, confirm in console, heartbeat, queue `REQUEST_DEVICE_STATUS`, confirm result row
