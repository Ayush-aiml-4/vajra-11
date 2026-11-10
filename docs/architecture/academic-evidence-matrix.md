# VAJRA — Academic Evidence Matrix (Prompt 0026)

Status labels: **VERIFIED** (repo + tests/docs evidence) · **PARTIAL** · **NOT IMPLEMENTED** · **BLOCKED**

## System design

| Requirement | Status | Evidence |
| :--- | :---: | :--- |
| Requirements / PRD | VERIFIED | `docs/product/PRD.md`, acceptance criteria |
| Architecture / data flow | VERIFIED | `docs/architecture/system-design.md`, `overview.md` |
| API list | VERIFIED | `docs/api/endpoints.md` |
| Trade-offs | VERIFIED | System design + Azure App Service guide |

## RDBMS

| Requirement | Status | Evidence |
| :--- | :---: | :--- |
| ≥5 related tables | VERIFIED | 17 app tables (User, Device, …) via migrations 0003–0007 |
| PK / FK / constraints | VERIFIED | Prisma schema + migration SQL |
| 3NF rationale | VERIFIED | `docs/architecture/sql-evidence.md`, `database.md` |
| Joins | VERIFIED | Views `vw_device_security_posture`, `vw_command_audit_history` |
| View | VERIFIED | Same views (applied on disposable PG) |
| Stored procedure / function | VERIFIED | `fn_record_command_execution_result` |
| Trigger | VERIFIED | `trg_prevent_audit_log_mutation` / `fn_prevent_audit_log_mutation` |
| Transactions | VERIFIED | Repository `$transaction` paths; PG integration tests |
| Indexes | VERIFIED | Migration 0007 analytics indexes |

## DP-900 / data

| Requirement | Status | Evidence |
| :--- | :---: | :--- |
| Structured / semi / unstructured classification | VERIFIED | `docs/architecture/data-classification.md` |
| Relational data | VERIFIED | PostgreSQL + Prisma |
| Non-relational example | PARTIAL | Documented as **planned** object/blob storage for future media; **not** implemented (no Azure Blob / Cosmos) |
| Analytics | VERIFIED | Analytics API + `docs/product/analytics-report.md`; PG test `dataSource: PERSISTED` |

## Cloud security

| Requirement | Status | Evidence |
| :--- | :---: | :--- |
| RBAC / authorization matrix | VERIFIED | `docs/security/authorization-matrix.md` + route guards |
| Password hashing | VERIFIED | Argon2id (`packages/security/src/password.ts`) |
| HTTPS | PARTIAL | App Service TLS runbook; **no live Azure URL** |
| Secrets management | VERIFIED (design) | App Settings / Key Vault documented; no secrets in repo |
| Input validation | VERIFIED | Express validators + schema checks |
| DB network restrictions | PARTIAL | Documented; not applied to a live Azure PG |
| Activity logging | VERIFIED | Append-only `AuditLog` + immutability trigger |

## Deliverables

| Requirement | Status | Evidence |
| :--- | :---: | :--- |
| README / setup | VERIFIED | Root `README.md`, deployment + postgresql-local docs |
| Dummy test logins | PARTIAL | Integration tests create ephemeral users; no fixed shared password published (preferred for security) |
| SQL / migration evidence | VERIFIED | `sql-evidence.md` + applied migrations |
| Analytics report | VERIFIED | `docs/product/analytics-report.md` |
| Threat model | VERIFIED | `docs/security/threat-model.md` |
| AI-tool acknowledgment | VERIFIED | `docs/security/ai-tool-acknowledgment.md` |

## Explicitly not claimed

- Live Azure App Service or PostgreSQL Flexible Server deployment
- Azure Blob Storage, Cosmos DB, Power BI
- Physical Windows/Android end-to-end device control without agent receipts
