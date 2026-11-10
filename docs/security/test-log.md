# VAJRA — Security Test Log (Prompt 0011D)

**Last Updated:** 2026-10-10  
**Scope:** Signed device events, command integrity, MFA step-up

## Commands Executed

```bash
npm run lint
npm test
npm run build
npx prisma validate
npx prisma generate
```

## Test Suites

| Suite | Focus |
| :--- | :--- |
| `tests/prompt0011d.test.ts` | Signed events, route binding, nonce replay, command transitions, step-up |
| Prior suites | Enrollment, auth foundation, events engine, ThreatCheck |

## Coverage Added (0011D)

- Valid signed device event ingestion via `POST /api/devices/:id/events`
- Invalid signature / route-device mismatch / nonce replay
- Client risk-score rejection
- Metadata redaction of secrets
- Legal vs illegal command transitions; terminal-state immutability
- Idempotent and conflicting command results
- MFA step-up required / wrong-scope / grant path
- Cross-user device isolation

## Limitations

- In-memory repository tests do **not** prove PostgreSQL row-level locking or concurrent uniqueness under load.
- No real Windows/Android agent is present; device execution remains pending until a signed `CommandResult` is received.
- PostgreSQL migration `0006_step_up_action_scope` is forward-only; apply with `prisma migrate deploy` against a disposable database before production use.


## Prompt 0011E — MFA Step-Up UI

- Frontend step-up modal, protected-action retry (once), cancellation, invalid-code handling.
- Server one-time step-up consumption after successful sensitive operations.
- Source-level tests in `tests/prompt0011d.test.ts` (Prompt 0011E describe block).
- Full browser automation and npm test suite deferred to post-feature verification phase.


## Prompt 0012 — Database, Analytics & Reporting

- Migration `0007_analytics_query_indexes` (composite indexes).
- Analytics `dataSource` / `windowDescription`; export cache headers.
- Docs: `data-classification.md`, `system-design.md`, updated `sql-evidence.md`, `analytics-report.md`.
- Tests: `tests/prompt0012-analytics.test.ts` (not executed in feature-first phase if deps unavailable).

## Prompt 0017 — Comprehensive verification

- Environment: Node v24.15.0; npm present; Java 21; no dotnet; no Android SDK; no psql/docker.
- npm install incomplete/timeout — automated lint/test/build/prisma **NOT RUN**.
- See docs/security/verification-report-0017.md for full PASS/FAIL/BLOCKED/NOT RUN inventory.
- No security checks weakened; no live agent or Azure deploy claimed.
