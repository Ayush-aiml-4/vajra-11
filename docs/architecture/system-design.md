# VAJRA — System Design Overview

**Status:** Architecture documentation (Prompt 0012)  
**Stack:** React 19 · TypeScript · Vite · Express · Prisma · PostgreSQL

---

## 1. Logical architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  Web Console (React SPA)                                    │
│  Session cookie · CSRF · MFA step-up UI · Analytics UI      │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS + same-origin API
┌────────────────────────────▼────────────────────────────────┐
│  vajra-api (Express)                                        │
│  Plane 1: User session + CSRF + Origin                      │
│  Plane 2: Device signature + nonce                          │
│  Plane 3: Command authorization + step-up scopes            │
│  Event engine · ThreatCheck · Analytics · Export            │
└────────────────────────────┬────────────────────────────────┘
                             │ Prisma / SQL
┌────────────────────────────▼────────────────────────────────┐
│  PostgreSQL                                                 │
│  Tables · FKs · CHECKs · Indexes                            │
│  Views: vw_device_security_posture, vw_command_audit_history │
│  Trigger: AuditLog append-only                              │
│  Function: fn_record_command_execution_result               │
└─────────────────────────────────────────────────────────────┘
```

Device agents (Windows / Android) are **planned product surfaces**; the API already exposes signed heartbeat, event, and command-receipt endpoints. Until agents ship, device-execution commands remain **QUEUED** pending a valid receipt.

---

## 2. Trust planes (summary)

1. **Plane 1 — User:** Password/passkey + optional TOTP; HTTP-only session; CSRF on mutations.
2. **Plane 2 — Device:** Ed25519/ECDSA request signatures; nonce replay protection; route/device binding.
3. **Plane 3 — Sensitive action:** MFA step-up (`POST /api/auth/step-up`) with action scope and one-time consumption after success.

---

## 3. Data flow highlights

| Flow | Path |
| :--- | :--- |
| Analytics | Authenticated `GET /api/analytics/summary` → user-scoped repository reads → JSON DTO (`dataSource: PERSISTED`) |
| Export | `GET /api/reports/export?format=json|csv` → redacted rows → attachment + `Cache-Control: no-store` |
| Commands | User creates QUEUED → device polls/acks → `CommandResult` transaction → terminal status |
| Events | Web or signed device ingest → `SecurityEvent` + optional notification + risk update |

---

## 4. Security boundaries

- Tenant isolation: every list/export filters by `session.userId` (or device ownership).
- Cross-user device IDs return **404**, not 403 enumeration.
- AuditLog is append-only (application + database trigger).
- ThreatCheck stores redacted URLs; CSV cells are formula-injection safe.

---

## 5. Deployment notes

- **Development:** In-memory repository fallback when PostgreSQL is unavailable (tests / preview).
- **Production target:** Azure Database for PostgreSQL + App Service/Container Apps; migrations applied forward-only (`0003`–`0007`).
- Live PostgreSQL verification is environment-dependent and is not assumed complete until explicitly run.
