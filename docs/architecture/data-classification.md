# VAJRA — Data Classification & Azure Data Concepts (DP-900 Alignment)

**Status:** Documentation (Prompt 0012)  
**Related:** `docs/architecture/sql-evidence.md`, `docs/architecture/system-design.md`, `docs/product/analytics-report.md`

---

## 1. Structured data (relational)

VAJRA’s primary system of record is **PostgreSQL** (Azure Database for PostgreSQL in a production deployment). Structured entities include:

| Domain | Tables (examples) | Characteristics |
| :--- | :--- | :--- |
| Identity | `User`, `UserCredential`, `PasskeyCredential`, `DeviceSession` | Strong keys, unique email, session hashes |
| Devices | `Device`, `DeviceCredential`, `EnrollmentChallenge`, `DeviceAuthNonce`, `DeviceHeartbeat` | Ownership FK, lifecycle enums, credential fingerprints |
| Security activity | `SecurityEvent`, `AuditLog`, `Notification`, `RiskAssessment` | Time-ordered, user-scoped indexes |
| Commands | `RemoteCommand`, `CommandResult` | State machine, receipt binding |
| ThreatCheck | `ThreatCheck`, `ThreatIndicator` | Domain + verdict + scored indicators |

These tables use UUID primary keys, foreign keys, unique constraints, CHECK constraints (risk/telemetry ranges in migrations), and indexes for ownership filters and timelines.

---

## 2. Semi-structured data (JSON)

Validated JSON is stored and exchanged without becoming a second database of record:

- **`SecurityEvent.metadata`**, **`RemoteCommand.payloadSummary`**, **`CommandResult.resultMetadata`**, **`Notification.metadata`**, **`RiskAssessment.factors` / `recommendations`**
- API request/response bodies (analytics summary, exports)

Server-side validation and redaction (`sanitizeLogMetadata`, event engine rules) strip credentials, tokens, and recovery material before persistence or logging.

---

## 3. Unstructured data (planned)

Not implemented in the current codebase:

- Binary evidence packages, PDF security reports, or raw agent logs as blob objects

**Planned (not implemented):** Azure Blob Storage for optional evidence archives, referenced by ID from PostgreSQL rows. Until then, reports are generated on demand as JSON/CSV from relational data only.

---

## 4. Transactional vs analytical workloads

| Workload | VAJRA usage | Characteristics |
| :--- | :--- | :--- |
| **Transactional (OLTP)** | Login, enrollment, command create/ack/result, event ingest, MFA step-up | Short ACID transactions, row-level integrity, low latency writes |
| **Analytical (OLAP-lite)** | `GET /api/analytics/summary`, report export, posture views | Read-heavy aggregates over recent user-scoped rows; not a separate warehouse |

Course-facing SQL views (`vw_device_security_posture`, `vw_command_audit_history`) support analytical-style joins **inside** the same PostgreSQL database. A dedicated warehouse is not required for MVP.

---

## 5. Realistic Azure architecture (target)

```text
[ Web Console (Static / App Service) ]
              |
              v
[ vajra-api  (App Service / Container Apps) ]
              |
      +-------+--------+
      |                |
      v                v
[ Azure Database    [ Azure Blob Storage ]
  for PostgreSQL ]    (planned evidence)
      |
      +-- structured tables, views, triggers, functions
```

- **Implemented path:** API + PostgreSQL (local or managed).
- **Planned only:** Blob for unstructured evidence; no Cosmos DB requirement for core product flows.
- **Credentials:** Database URL via environment (`DATABASE_URL`); never commit secrets.

---

## 6. Classification labels used in product

| Label | Meaning |
| :--- | :--- |
| **PERSISTED** | Aggregates/export built only from authenticated user’s database rows |
| **SAMPLE / Demo** | UI preview devices or demo event scenarios; must not be mixed into live analytics counts |
| **REDACTED** | URL query secrets and forbidden metadata keys removed before store/export |
