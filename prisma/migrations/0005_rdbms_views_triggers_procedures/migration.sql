-- VAJRA — Migration 0005_rdbms_views_triggers_procedures
-- Provider: PostgreSQL
-- Purpose: Course-required RDBMS objects:
--   1. View: vw_device_security_posture (multi-table JOIN across Device, User, DeviceCredential, DeviceHeartbeat, RiskAssessment, SecurityEvent)
--   2. View: vw_command_audit_history (multi-table JOIN across RemoteCommand, Device, User, CommandResult)
--   3. Trigger & Function: trg_prevent_audit_log_mutation / fn_prevent_audit_log_mutation() enforcing append-only immutability on AuditLog
--   4. Stored Function: fn_record_command_execution_result(...) atomically recording a CommandResult and transitioning RemoteCommand state

-- ============================================================================
-- 1. SQL View: vw_device_security_posture
-- Summarizes each enrolled device's identity, owner, active cryptographic key
-- posture, latest heartbeat telemetry, latest risk assessment, and high-risk
-- event count.
-- ============================================================================
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
    SELECT
        c."id",
        c."keyAlgorithm",
        c."publicKeyFingerprint",
        c."hardwareBacked",
        c."status"
    FROM "DeviceCredential" c
    WHERE c."deviceId" = d."id"
    ORDER BY c."active" DESC, c."createdAt" DESC
    LIMIT 1
) dc ON TRUE
LEFT JOIN LATERAL (
    SELECT
        h."batteryLevel",
        h."charging",
        h."networkType",
        h."locationPermissionGranted",
        h."receivedAt"
    FROM "DeviceHeartbeat" h
    WHERE h."deviceId" = d."id"
    ORDER BY h."receivedAt" DESC
    LIMIT 1
) hb ON TRUE
LEFT JOIN LATERAL (
    SELECT
        r."score",
        r."status",
        r."updatedAt"
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

-- ============================================================================
-- 2. SQL View: vw_command_audit_history
-- Joins RemoteCommand with target Device, issuing User, and CommandResult to
-- provide a complete end-to-end audit trail of remote protection and recovery
-- actions along with execution latency.
-- ============================================================================
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

-- ============================================================================
-- 3. Append-Only Audit Immutability Trigger: trg_prevent_audit_log_mutation
-- Enforces the cryptographic hash-chained AuditLog contract at the database
-- engine layer by rejecting any UPDATE or DELETE statement on "AuditLog".
-- ============================================================================
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

DROP TRIGGER IF EXISTS "trg_prevent_audit_log_mutation" ON "AuditLog";

CREATE TRIGGER "trg_prevent_audit_log_mutation"
BEFORE UPDATE OR DELETE ON "AuditLog"
FOR EACH ROW
EXECUTE FUNCTION "fn_prevent_audit_log_mutation"();

-- ============================================================================
-- 4. Stored Function: fn_record_command_execution_result
-- Atomically records an agent-submitted CommandResult and transitions the
-- parent RemoteCommand to COMPLETED or FAILED (with idempotent replay support).
-- ============================================================================
CREATE OR REPLACE FUNCTION "fn_record_command_execution_result"(
    p_result_id UUID,
    p_command_id UUID,
    p_device_id UUID,
    p_status TEXT,
    p_safe_message TEXT,
    p_error_code TEXT DEFAULT NULL,
    p_device_timestamp TIMESTAMP(3) DEFAULT NULL,
    p_result_metadata JSONB DEFAULT '{}'::JSONB,
    p_received_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP
)
RETURNS TABLE (
    "resultId" UUID,
    "commandId" UUID,
    "finalStatus" TEXT,
    "idempotentReplay" BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing_result_id UUID;
    v_existing_status TEXT;
    v_cmd_device_id UUID;
BEGIN
    SELECT d."deviceId"
      INTO v_cmd_device_id
      FROM "RemoteCommand" d
     WHERE d."id" = p_command_id
       FOR UPDATE;

    IF v_cmd_device_id IS NULL THEN
        RAISE EXCEPTION 'COMMAND_NOT_FOUND: RemoteCommand % does not exist.', p_command_id
            USING ERRCODE = 'P0002';
    END IF;

    IF v_cmd_device_id <> p_device_id THEN
        RAISE EXCEPTION 'COMMAND_DEVICE_MISMATCH: RemoteCommand % does not belong to device %.', p_command_id, p_device_id
            USING ERRCODE = '42501';
    END IF;

    SELECT cr."id", cr."status"
      INTO v_existing_result_id, v_existing_status
      FROM "CommandResult" cr
     WHERE cr."commandId" = p_command_id;

    IF v_existing_result_id IS NOT NULL THEN
        RETURN QUERY SELECT v_existing_result_id, p_command_id, v_existing_status, TRUE;
        RETURN;
    END IF;

    INSERT INTO "CommandResult" (
        "id",
        "commandId",
        "deviceId",
        "status",
        "receivedAt",
        "completedAt",
        "errorCode",
        "safeMessage",
        "deviceTimestamp",
        "resultMetadata"
    ) VALUES (
        p_result_id,
        p_command_id,
        p_device_id,
        p_status,
        p_received_at,
        p_received_at,
        p_error_code,
        p_safe_message,
        p_device_timestamp,
        COALESCE(p_result_metadata, '{}'::JSONB)
    );

    UPDATE "RemoteCommand"
       SET "status" = p_status,
           "statusMessage" = p_safe_message,
           "completedAt" = p_received_at,
           "acknowledgedAt" = COALESCE("acknowledgedAt", p_received_at),
           "deliveredAt" = COALESCE("deliveredAt", p_received_at)
     WHERE "id" = p_command_id;

    RETURN QUERY SELECT p_result_id, p_command_id, p_status, FALSE;
END;
$$;
