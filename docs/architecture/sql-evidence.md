# VAJRA — PostgreSQL Schema, Migrations & RDBMS Evidence (`docs/architecture/sql-evidence.md`)

## 1. Overview & Migration History

VAJRA uses **PostgreSQL** with **Prisma ORM (`prisma-client-js`)** and maintains a strict, forward-only migration history under `prisma/migrations/`:

| Migration | Purpose |
| :--- | :--- |
| `0003_identity_foundation` | Initial identity foundation (`User`, `UserCredential`, `PasskeyCredential`, `Device`, `DeviceCredential`, `DeviceSession`, `AuditLog`). |
| `0004_complete_schema_foundation` | Reconciles `prisma/schema.prisma` with the migration history in dependency-safe order: adds `DeviceCredentialStatus` enum, adds missing columns on `Device` (`lastSeenAt`, `compromisedAt`) and `DeviceCredential` (`status`, `rotatedAt`), creates `EnrollmentChallenge`, `DeviceAuthNonce`, `Notification`, `RemoteCommand`, `CommandResult`, `SecurityEvent`, `DeviceHeartbeat`, `RiskAssessment`, `ThreatCheck`, and `ThreatIndicator`, and adds foreign keys, indexes, and validated `CHECK` constraints. |
| `0005_rdbms_views_triggers_procedures` | Adds course-required PostgreSQL database objects: `vw_device_security_posture` view, `vw_command_audit_history` view, `trg_prevent_audit_log_mutation` append-only immutability trigger + `fn_prevent_audit_log_mutation()` trigger function, and `fn_record_command_execution_result(...)` atomic stored function. |
| `0006_step_up_action_scope` | Adds `DeviceSession.stepUpActionScope` for MFA step-up action binding (Prompt 0011D). |
| `0007_analytics_query_indexes` | Composite indexes for analytics/export query patterns: `SecurityEvent(userId, occurredAt)`, `ThreatCheck(userId, checkedAt)`, `Notification(userId, dismissedAt, readAt)`, `RemoteCommand(issuerUserId, requestedAt)`. |

---

## 2. Normalized Relational Schema (17 Related Tables Targeting 3NF)

Every entity has a UUID primary key (`@id @default(uuid()) @db.Uuid`), explicit foreign keys with referential actions (`ON DELETE CASCADE` or `ON DELETE SET NULL`), and no repeating groups or transitive functional dependencies:

1. **`User`** (`id` PK, `email` UNIQUE) — Account owner identity and login lockout state.
2. **`UserCredential`** (`id` PK, `userId` UNIQUE FK -> `User.id`) — Isolated Argon2id password hash, AES-256-GCM encrypted TOTP secret, and SHA-256 recovery code hashes.
3. **`PasskeyCredential`** (`id` PK, `userId` FK -> `User.id`, `credentialId` UNIQUE) — WebAuthn / FIDO2 public key credentials.
4. **`Device`** (`id` PK, `userId` FK -> `User.id`) — Enrolled Windows (`ASUS TUF F16`) and Android (`Android Phone`) endpoints.
5. **`DeviceCredential`** (`id` PK, `deviceId` FK -> `Device.id`, `publicKeyFingerprint` UNIQUE) — Per-device Ed25519 / ECDSA P-256 public key lifecycle (`PENDING_CONFIRMATION`, `ACTIVE`, `ROTATED`, `REVOKED`).
6. **`EnrollmentChallenge`** (`id` PK, `deviceId` FK -> `Device.id`, `tokenHash` UNIQUE, `nonce` UNIQUE) — Short-lived cryptographic enrollment challenges.
7. **`DeviceAuthNonce`** (`id` PK, `deviceId` FK -> `Device.id`, UNIQUE `(deviceId, nonce)`) — Replay-protection nonce ledger for signed agent requests.
8. **`DeviceSession`** (`id` PK, `userId` FK -> `User.id`, `deviceId` nullable FK -> `Device.id`, `tokenHash` UNIQUE) — Server-side session ledger with SHA-256 token hashes and CSRF token hashes.
9. **`AuditLog`** (`id` PK, `sequenceNumber` UNIQUE SERIAL, `actorUserId` nullable FK -> `User.id`, `actorDeviceId` nullable FK -> `Device.id`, `entryHash` UNIQUE) — Append-only SHA-256 hash-chained audit ledger.
10. **`Notification`** (`id` PK, `userId` FK -> `User.id`, `relatedDeviceId` nullable FK -> `Device.id`) — Persistent user security notifications with read/dismiss state.
11. **`RemoteCommand`** (`id` PK, `deviceId` FK -> `Device.id`, `issuerUserId` FK -> `User.id`) — Allowlisted defensive/recovery commands (`LOCK_DEVICE`, `RING_DEVICE`, `REQUEST_LOCATION`, `DISPLAY_RECOVERY_MESSAGE`, `ENABLE_LOST_MODE`, `CONTAIN_DEVICE`, `CLEAR_RECOVERY_STATE`).
12. **`CommandResult`** (`id` PK, `commandId` UNIQUE FK -> `RemoteCommand.id`, `deviceId` FK -> `Device.id`) — Agent execution outcome (1:1 with `RemoteCommand`).
13. **`SecurityEvent`** (`id` PK, `userId` FK -> `User.id`, `deviceId` nullable FK -> `Device.id`) — Normalized telemetry and security event stream.
14. **`DeviceHeartbeat`** (`id` PK, `deviceId` FK -> `Device.id`) — Signed periodic health, battery, and network telemetry.
15. **`RiskAssessment`** (`id` PK, `userId` FK -> `User.id`, `deviceId` nullable FK -> `Device.id`) — Deterministic 0–100 security posture snapshots.
16. **`ThreatCheck` & `ThreatIndicator`** (`ThreatCheck.id` PK, `userId` FK -> `User.id`, `deviceId` nullable FK -> `Device.id`; `ThreatIndicator.id` PK, `threatCheckId` FK -> `ThreatCheck.id`) — Normalized 1:N URL/link inspection records and individual risk indicators.

### Validated `CHECK` Constraints (`0004_complete_schema_foundation`)
```sql
ALTER TABLE "User" ADD CONSTRAINT "User_failedLoginAttempts_check" CHECK ("failedLoginAttempts" >= 0);
ALTER TABLE "Device" ADD CONSTRAINT "Device_currentRiskScore_check" CHECK ("currentRiskScore" >= 0 AND "currentRiskScore" <= 100);
ALTER TABLE "DeviceHeartbeat" ADD CONSTRAINT "DeviceHeartbeat_batteryLevel_check" CHECK ("batteryLevel" IS NULL OR ("batteryLevel" >= 0 AND "batteryLevel" <= 100));
ALTER TABLE "RiskAssessment" ADD CONSTRAINT "RiskAssessment_score_check" CHECK ("score" >= 0 AND "score" <= 100);
ALTER TABLE "ThreatCheck" ADD CONSTRAINT "ThreatCheck_riskScore_check" CHECK ("riskScore" >= 0 AND "riskScore" <= 100);
ALTER TABLE "ThreatIndicator" ADD CONSTRAINT "ThreatIndicator_weight_check" CHECK ("weight" >= 0 AND "weight" <= 100);
```

---

## 3. SQL Views (`0005_rdbms_views_triggers_procedures`)

### 3.1 `vw_device_security_posture`
Combines `Device`, `User`, active `DeviceCredential`, latest `DeviceHeartbeat`, latest `RiskAssessment`, and aggregated `SecurityEvent` counts using `INNER JOIN` and `LEFT JOIN LATERAL`:

```sql
CREATE OR REPLACE VIEW "vw_device_security_posture" AS
SELECT
    d."id" AS "deviceId",
    d."userId" AS "ownerUserId",
    u."email" AS "ownerEmail",
    u."displayName" AS "ownerDisplayName",
    d."name" AS "deviceName",
    d."deviceType",
    d."lifecycleState",
    d."connectivityStatus",
    d."osVersion",
    d."agentVersion",
    d."currentRiskScore",
    d."currentRiskLevel",
    d."lastHeartbeatAt",
    d."lastSeenAt",
    d."enrolledAt",
    dc."id" AS "activeCredentialId",
    dc."keyAlgorithm",
    dc."publicKeyFingerprint",
    dc."hardwareBacked",
    dc."status" AS "credentialStatus",
    hb."batteryLevel" AS "latestBatteryLevel",
    hb."charging" AS "latestChargingState",
    hb."networkType" AS "latestNetworkType",
    hb."locationPermissionGranted" AS "latestLocationPermission",
    hb."receivedAt" AS "latestHeartbeatReceivedAt",
    ra."score" AS "assessedPostureScore",
    ra."status" AS "assessedPostureStatus",
    ra."updatedAt" AS "assessedPostureUpdatedAt",
    COALESCE(ev_stats."totalSecurityEvents", 0) AS "totalSecurityEvents",
    COALESCE(ev_stats."highOrCriticalEvents", 0) AS "highOrCriticalEvents"
FROM "Device" d
INNER JOIN "User" u
    ON u."id" = d."userId"
LEFT JOIN LATERAL (
    SELECT c."id", c."keyAlgorithm", c."publicKeyFingerprint", c."hardwareBacked", c."status"
    FROM "DeviceCredential" c
    WHERE c."deviceId" = d."id"
    ORDER BY c."active" DESC, c."createdAt" DESC
    LIMIT 1
) dc ON TRUE
LEFT JOIN LATERAL (
    SELECT h."batteryLevel", h."charging", h."networkType", h."locationPermissionGranted", h."receivedAt"
    FROM "DeviceHeartbeat" h
    WHERE h."deviceId" = d."id"
    ORDER BY h."receivedAt" DESC
    LIMIT 1
) hb ON TRUE
LEFT JOIN LATERAL (
    SELECT r."score", r."status", r."updatedAt"
    FROM "RiskAssessment" r
    WHERE r."deviceId" = d."id"
    ORDER BY r."updatedAt" DESC
    LIMIT 1
) ra ON TRUE
LEFT JOIN LATERAL (
    SELECT
        COUNT(*)::INTEGER AS "totalSecurityEvents",
        COUNT(*) FILTER (WHERE se."severity" IN ('HIGH', 'CRITICAL'))::INTEGER AS "highOrCriticalEvents"
    FROM "SecurityEvent" se
    WHERE se."deviceId" = d."id"
) ev_stats ON TRUE;
```

### 3.2 `vw_command_audit_history`
Joins `RemoteCommand` with `Device`, `User`, and `CommandResult` and computes execution duration in seconds:

```sql
CREATE OR REPLACE VIEW "vw_command_audit_history" AS
SELECT
    rc."id" AS "commandId",
    rc."deviceId",
    d."name" AS "deviceName",
    d."deviceType",
    d."lifecycleState" AS "deviceLifecycleState",
    rc."issuerUserId",
    u."email" AS "issuerEmail",
    u."displayName" AS "issuerDisplayName",
    rc."actionType",
    rc."status" AS "commandStatus",
    rc."statusMessage",
    rc."nonce" AS "commandNonce",
    rc."payloadSummary",
    rc."requestedAt",
    rc."deliveredAt",
    rc."acknowledgedAt",
    rc."completedAt" AS "commandCompletedAt",
    rc."expiresAt",
    cr."id" AS "resultId",
    cr."status" AS "executionResultStatus",
    cr."receivedAt" AS "resultReceivedAt",
    cr."completedAt" AS "resultCompletedAt",
    cr."errorCode" AS "resultErrorCode",
    cr."safeMessage" AS "resultSafeMessage",
    cr."deviceTimestamp" AS "resultDeviceTimestamp",
    cr."resultMetadata",
    CASE
        WHEN rc."completedAt" IS NOT NULL THEN
            EXTRACT(EPOCH FROM (rc."completedAt" - rc."requestedAt"))::NUMERIC(12, 3)
        ELSE NULL
    END AS "executionDurationSeconds"
FROM "RemoteCommand" rc
INNER JOIN "Device" d
    ON d."id" = rc."deviceId"
INNER JOIN "User" u
    ON u."id" = rc."issuerUserId"
LEFT JOIN "CommandResult" cr
    ON cr."commandId" = rc."id";
```

---

## 4. Append-Only Audit Immutability Trigger & Stored Function

### 4.1 Trigger: `trg_prevent_audit_log_mutation`
VAJRA's `AuditLog` table forms a cryptographic hash chain (`previousEntryHash -> entryHash`). Any `UPDATE` or `DELETE` on `AuditLog` would invalidate the hash chain. The trigger enforces append-only immutability at the PostgreSQL engine level, and is 100% compatible with `appendAuditEvent()` which only executes `SELECT` and `INSERT`:

```sql
CREATE OR REPLACE FUNCTION "fn_prevent_audit_log_mutation"()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'VAJRA_AUDIT_IMMUTABLE: AuditLog records are append-only and cannot be modified or deleted (attempted % on sequenceNumber=%).',
        TG_OP, OLD."sequenceNumber"
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER "trg_prevent_audit_log_mutation"
BEFORE UPDATE OR DELETE ON "AuditLog"
FOR EACH ROW
EXECUTE FUNCTION "fn_prevent_audit_log_mutation"();
```

### 4.2 Stored Function: `fn_record_command_execution_result`
Atomically locks the `RemoteCommand` row (`FOR UPDATE`), checks for idempotent replay in `CommandResult`, inserts the `CommandResult` row, and updates the parent `RemoteCommand` status and timestamps in a single database call.

---

## 5. Meaningful Multi-Table JOIN Queries

### Query 1 — Device Security Posture & Active Hardware Key Verification
```sql
SELECT
    "deviceId",
    "deviceName",
    "deviceType",
    "lifecycleState",
    "keyAlgorithm",
    "hardwareBacked",
    "latestBatteryLevel",
    "assessedPostureScore",
    "highOrCriticalEvents"
FROM "vw_device_security_posture"
WHERE "ownerUserId" = $1
ORDER BY "highOrCriticalEvents" DESC, "deviceName" ASC;
```

### Query 2 — ThreatCheck Inspection History with Aggregated Indicators
```sql
SELECT
    tc."id" AS "threatCheckId",
    tc."normalizedDomain",
    tc."verdict",
    tc."riskScore",
    tc."checkedAt",
    d."name" AS "deviceName",
    COUNT(ti."id")::INTEGER AS "indicatorCount",
    COALESCE(
        JSONB_AGG(
            JSONB_BUILD_OBJECT(
                'code', ti."code",
                'severity', ti."severity",
                'title', ti."title",
                'weight', ti."weight"
            )
            ORDER BY ti."weight" DESC
        ) FILTER (WHERE ti."id" IS NOT NULL),
        '[]'::JSONB
    ) AS "indicators"
FROM "ThreatCheck" tc
LEFT JOIN "Device" d
    ON d."id" = tc."deviceId"
LEFT JOIN "ThreatIndicator" ti
    ON ti."threatCheckId" = tc."id"
WHERE tc."userId" = $1
GROUP BY tc."id", d."name"
ORDER BY tc."checkedAt" DESC
LIMIT 25;
```

### Query 3 — User-Scoped Analytics Summary Aggregation (`GET /api/analytics/summary`)
```sql
SELECT
    tc."verdict",
    COUNT(tc."id")::INTEGER AS "checkCount",
    ROUND(AVG(tc."riskScore"))::INTEGER AS "averageRiskScore",
    COUNT(ti."id") FILTER (WHERE ti."severity" IN ('HIGH', 'CRITICAL'))::INTEGER AS "highSeverityIndicatorCount"
FROM "ThreatCheck" tc
LEFT JOIN "ThreatIndicator" ti
    ON ti."threatCheckId" = tc."id"
WHERE tc."userId" = $1
GROUP BY tc."verdict"
ORDER BY "checkCount" DESC;
```

---

## 6. Transaction Examples (`prisma.$transaction`)

VAJRA uses ACID transactions across all multi-step state mutations in `PrismaIdentityRepository` (`src/server/db/repository.ts`):

1. **`createUserWithCredential`** — Atomically inserts `User` and `UserCredential` via nested Prisma write.
2. **`createEnrollmentPendingDevice`** — `this.prisma.$transaction` creating the `Device` in `ENROLLMENT_PENDING` state and its `EnrollmentChallenge`.
3. **`submitDevicePublicKey`** — `this.prisma.$transaction` marking `EnrollmentChallenge.consumedAt`, updating `Device`, and creating `DeviceCredential` (`PENDING_CONFIRMATION`).
4. **`confirmDeviceEnrollment`** — `this.prisma.$transaction` activating `DeviceCredential` (`ACTIVE`) and transitioning `Device.lifecycleState` to `TRUSTED`.
5. **`rotateDeviceCredential`** — `this.prisma.$transaction` marking previous credentials `ROTATED` and inserting the new `ACTIVE` credential.
6. **`revokeDeviceAndCredentials`** — `this.prisma.$transaction` revoking all active credentials and transitioning `Device.lifecycleState` to `REVOKED`.
7. **`appendAuditEvent`** — `this.prisma.$transaction` reading the latest `sequenceNumber` + `entryHash` and inserting the next linked `AuditLog` entry.
8. **`recordCommandExecutionResult`** — `this.prisma.$transaction` checking for an existing `CommandResult` (idempotent replay), updating `RemoteCommand` (`COMPLETED` / `FAILED`), and inserting the `CommandResult` atomically.

---

## 7. Index Inventory

All frequently searched foreign keys, status columns, hashes, and time-range columns are indexed across migrations `0003` and `0004`:

- **Identity & Sessions**: `User_email_key`, `User_status_idx`, `PasskeyCredential_userId_idx`, `DeviceSession_tokenHash_key`, `DeviceSession_userId_idx`, `DeviceSession_expiresAt_idx`
- **Devices & Cryptography**: `Device_userId_idx`, `Device_lifecycleState_idx`, `DeviceCredential_publicKeyFingerprint_key`, `DeviceCredential_deviceId_idx`, `DeviceCredential_status_idx`, `EnrollmentChallenge_tokenHash_key`, `EnrollmentChallenge_expiresAt_idx`, `DeviceAuthNonce_deviceId_nonce_key`, `DeviceAuthNonce_expiresAt_idx`
- **Audit & Telemetry**: `AuditLog_sequenceNumber_key`, `AuditLog_entryHash_key`, `AuditLog_actorUserId_idx`, `AuditLog_eventType_idx`, `AuditLog_timestamp_idx`, `SecurityEvent_userId_idx`, `SecurityEvent_deviceId_idx`, `SecurityEvent_category_idx`, `SecurityEvent_severity_idx`, `SecurityEvent_occurredAt_idx`, `DeviceHeartbeat_deviceId_idx`, `DeviceHeartbeat_receivedAt_idx`, `RiskAssessment_userId_idx`, `RiskAssessment_deviceId_idx`, `RiskAssessment_updatedAt_idx`
- **Commands & Notifications**: `Notification_userId_idx`, `Notification_createdAt_idx`, `Notification_readAt_idx`, `Notification_severity_idx`, `RemoteCommand_deviceId_idx`, `RemoteCommand_issuerUserId_idx`, `RemoteCommand_status_idx`, `RemoteCommand_requestedAt_idx`, `RemoteCommand_expiresAt_idx`, `CommandResult_commandId_key`, `CommandResult_deviceId_idx`
- **ThreatCheck**: `ThreatCheck_userId_idx`, `ThreatCheck_deviceId_idx`, `ThreatCheck_normalizedDomain_idx`, `ThreatCheck_verdict_idx`, `ThreatCheck_checkedAt_idx`, `ThreatIndicator_threatCheckId_idx`, `ThreatIndicator_code_idx`, `ThreatIndicator_severity_idx`

---

## 8. Safe Execution Instructions

To validate and apply migrations safely against a PostgreSQL database without destructive resets:

```bash
# 1. Validate Prisma schema syntax and relations
DATABASE_URL="postgresql://user:password@localhost:5432/vajra" npx prisma validate

# 2. Generate typed Prisma Client
npx prisma generate

# 3. Apply pending forward-only migrations (0003 -> 0004 -> 0005)
npx prisma migrate deploy

# 4. Seed initial sample accounts and enrolled devices (idempotent upsert)
npm run db:seed
```


---

## 8. Analytics query indexes (Migration 0007)

These composite indexes support the documented API access patterns without changing application semantics:

| Index | Supports |
| :--- | :--- |
| `SecurityEvent_userId_occurredAt_idx` | User activity timeline and analytics event window |
| `ThreatCheck_userId_checkedAt_idx` | ThreatCheck history pagination and export |
| `Notification_userId_dismissedAt_readAt_idx` | Unread/open alert counts |
| `RemoteCommand_issuerUserId_requestedAt_idx` | Issuer-scoped recent command lists |

**Note:** HTTP analytics use the repository layer so tests can run against the in-memory adapter. The SQL views and `fn_record_command_execution_result` remain the course evidence for multi-table JOINs, triggers, and transactional procedures on PostgreSQL.

---

## 9. Representative multi-table JOIN (conceptual)

```sql
-- Five+ related tables: command audit with owner, device, result, and optional latest heartbeat
SELECT c."commandId", c."deviceName", c."issuerEmail", c."commandStatus",
       c."executionResultStatus", h."receivedAt" AS "lastHeartbeatAt"
FROM "vw_command_audit_history" c
LEFT JOIN LATERAL (
  SELECT hb."receivedAt"
  FROM "DeviceHeartbeat" hb
  WHERE hb."deviceId" = c."deviceId"
  ORDER BY hb."receivedAt" DESC
  LIMIT 1
) h ON TRUE
WHERE c."issuerUserId" = $1
ORDER BY c."requestedAt" DESC
LIMIT 50;
```
