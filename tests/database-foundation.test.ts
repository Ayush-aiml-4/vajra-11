/**
 * VAJRA — Prompt 0011A Database Foundation & RDBMS Consistency Test Suite
 *
 * Verifies:
 * 1. Complete consistency between prisma/schema.prisma models/fields/enums/indexes and the
 *    cumulative forward-only SQL migrations (0003–0007).
 * 2. Presence and validity of validated CHECK constraints in 0004_complete_schema_foundation.
 * 3. Presence and validity of RDBMS views (vw_device_security_posture, vw_command_audit_history),
 *    append-only AuditLog immutability trigger (trg_prevent_audit_log_mutation / fn_prevent_audit_log_mutation),
 *    and atomic stored function (fn_record_command_execution_result) in 0005_rdbms_views_triggers_procedures.
 * 4. Compatibility between the AuditLog immutability trigger and appendAuditEvent (strictly INSERT-only).
 * 5. Atomic recordCommandExecutionResult behavior & idempotent replay in the repository layer.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';

const ROOT_DIR = process.cwd();
const SCHEMA_PATH = path.join(ROOT_DIR, 'prisma', 'schema.prisma');
const MIGRATION_0003_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0003_identity_foundation',
  'migration.sql'
);
const MIGRATION_0004_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0004_complete_schema_foundation',
  'migration.sql'
);
const MIGRATION_0005_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0005_rdbms_views_triggers_procedures',
  'migration.sql'
);
const MIGRATION_0006_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0006_step_up_action_scope',
  'migration.sql'
);
const MIGRATION_0007_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0007_analytics_query_indexes',
  'migration.sql'
);
const MIGRATION_0008_PATH = path.join(
  ROOT_DIR,
  'prisma',
  'migrations',
  '0008_enrollment_passcode_verification',
  'migration.sql'
);
const SQL_EVIDENCE_DOC_PATH = path.join(ROOT_DIR, 'docs', 'architecture', 'sql-evidence.md');

function parsePrismaSchemaModelsAndEnums(schemaText: string): {
  enums: Map<string, string[]>;
  models: Map<string, string[]>;
} {
  const enums = new Map<string, string[]>();
  const models = new Map<string, string[]>();

  const enumRegex = /enum\s+([A-Za-z0-9_]+)\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = enumRegex.exec(schemaText)) !== null) {
    const enumName = match[1];
    const values = match[2]
      .split('\n')
      .map((line) => line.replace(/\/\/.*$/, '').trim())
      .filter((line) => line.length > 0);
    enums.set(enumName, values);
  }

  const scalarTypes = new Set([
    'String',
    'Int',
    'BigInt',
    'Boolean',
    'DateTime',
    'Json',
    'Float',
    'Decimal',
    'Bytes',
  ]);

  const modelRegex = /model\s+([A-Za-z0-9_]+)\s*\{([^}]*)\}/g;
  while ((match = modelRegex.exec(schemaText)) !== null) {
    const modelName = match[1];
    const bodyLines = match[2]
      .split('\n')
      .map((line) => line.replace(/\/\/.*$/, '').trim())
      .filter((line) => line.length > 0 && !line.startsWith('@@'));

    const scalarFields: string[] = [];
    for (const line of bodyLines) {
      const tokens = line.split(/\s+/);
      if (tokens.length < 2) continue;
      const fieldName = tokens[0];
      const rawType = tokens[1].replace(/[\?\[\]]/g, '');
      if (scalarTypes.has(rawType) || enums.has(rawType)) {
        scalarFields.push(fieldName);
      }
    }
    models.set(modelName, scalarFields);
  }

  return { enums, models };
}

function parseCumulativeMigrationTablesAndColumns(sqlTexts: string[]): {
  enums: Set<string>;
  tables: Map<string, Set<string>>;
} {
  const combinedSql = sqlTexts.join('\n');
  const enums = new Set<string>();
  const tables = new Map<string, Set<string>>();

  const enumRegex = /CREATE\s+TYPE\s+"([^"]+)"\s+AS\s+ENUM/gi;
  let match: RegExpExecArray | null;
  while ((match = enumRegex.exec(combinedSql)) !== null) {
    enums.add(match[1]);
  }

  const createTableRegex = /CREATE\s+TABLE\s+"([^"]+)"\s*\(([\s\S]*?)\);/gi;
  while ((match = createTableRegex.exec(combinedSql)) !== null) {
    const tableName = match[1];
    const body = match[2];
    const cols = tables.get(tableName) ?? new Set<string>();
    const colLines = body.split('\n');
    for (const line of colLines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('"')) {
        const colMatch = /^"([^"]+)"/.exec(trimmed);
        if (colMatch) {
          cols.add(colMatch[1]);
        }
      }
    }
    tables.set(tableName, cols);
  }

  const alterTableRegex = /ALTER\s+TABLE\s+"([^"]+)"\s+([\s\S]*?);/gi;
  while ((match = alterTableRegex.exec(combinedSql)) !== null) {
    const tableName = match[1];
    const alterBody = match[2];
    const cols = tables.get(tableName) ?? new Set<string>();
    const addColRegex = /ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"([^"]+)"/gi;
    let colMatch: RegExpExecArray | null;
    while ((colMatch = addColRegex.exec(alterBody)) !== null) {
      cols.add(colMatch[1]);
    }
    tables.set(tableName, cols);
  }

  return { enums, tables };
}

describe('VAJRA Prompt 0011A — Database Foundation & RDBMS Verification Suite', () => {
  it('1. Every model, scalar field, and enum in prisma/schema.prisma is present in cumulative migrations (0003–0007)', () => {
    const schemaText = fs.readFileSync(SCHEMA_PATH, 'utf8');
    const sql0003 = fs.readFileSync(MIGRATION_0003_PATH, 'utf8');
    const sql0004 = fs.readFileSync(MIGRATION_0004_PATH, 'utf8');
    const sql0006 = fs.readFileSync(MIGRATION_0006_PATH, 'utf8');
    const sql0007 = fs.readFileSync(MIGRATION_0007_PATH, 'utf8');
    const sql0008 = fs.readFileSync(MIGRATION_0008_PATH, 'utf8');

    const { enums: schemaEnums, models: schemaModels } = parsePrismaSchemaModelsAndEnums(schemaText);
    // Cumulative forward-only migrations through 0008 (ALTER TABLE columns appear in later files)
    const { enums: migratedEnums, tables: migratedTables } =
      parseCumulativeMigrationTablesAndColumns([sql0003, sql0004, sql0006, sql0007, sql0008]);

    // Verify all 8 enums exist in migrations
    assert.equal(schemaEnums.size, 8, 'Expected 8 enums in prisma/schema.prisma');
    for (const enumName of schemaEnums.keys()) {
      assert.ok(
        migratedEnums.has(enumName),
        `Enum "${enumName}" in prisma/schema.prisma is missing from SQL migrations`
      );
    }

    // Verify all 17 models exist in migrations with every scalar/enum column
    assert.equal(schemaModels.size, 17, 'Expected 17 models in prisma/schema.prisma');
    for (const [modelName, fields] of schemaModels.entries()) {
      const tableCols = migratedTables.get(modelName);
      assert.ok(
        tableCols,
        `Model "${modelName}" in prisma/schema.prisma is missing CREATE TABLE in migrations`
      );
      for (const field of fields) {
        assert.ok(
          tableCols.has(field),
          `Column "${modelName}.${field}" in prisma/schema.prisma is missing from cumulative migrations`
        );
      }
    }
  });

  it('2. Migration 0004 defines foreign keys, unique constraints, indexes, and validated CHECK constraints', () => {
    const sql0004 = fs.readFileSync(MIGRATION_0004_PATH, 'utf8');

    // Verify ThreatCheck and ThreatIndicator 1:N normalized relation
    assert.match(sql0004, /CREATE TABLE "ThreatCheck"/);
    assert.match(sql0004, /CREATE TABLE "ThreatIndicator"/);
    assert.match(
      sql0004,
      /ALTER TABLE "ThreatIndicator" ADD CONSTRAINT "ThreatIndicator_threatCheckId_fkey" FOREIGN KEY \("threatCheckId"\) REFERENCES "ThreatCheck"\("id"\) ON DELETE CASCADE/
    );

    // Verify CHECK constraints on risk scores and telemetry ranges
    assert.match(sql0004, /CONSTRAINT "User_failedLoginAttempts_check" CHECK \("failedLoginAttempts" >= 0\)/);
    assert.match(
      sql0004,
      /CONSTRAINT "Device_currentRiskScore_check" CHECK \("currentRiskScore" >= 0 AND "currentRiskScore" <= 100\)/
    );
    assert.match(
      sql0004,
      /CONSTRAINT "DeviceHeartbeat_batteryLevel_check" CHECK \("batteryLevel" IS NULL OR \("batteryLevel" >= 0 AND "batteryLevel" <= 100\)\)/
    );
    assert.match(
      sql0004,
      /CONSTRAINT "RiskAssessment_score_check" CHECK \("score" >= 0 AND "score" <= 100\)/
    );
    assert.match(
      sql0004,
      /CONSTRAINT "ThreatCheck_riskScore_check" CHECK \("riskScore" >= 0 AND "riskScore" <= 100\)/
    );
    assert.match(
      sql0004,
      /CONSTRAINT "ThreatIndicator_weight_check" CHECK \("weight" >= 0 AND "weight" <= 100\)/
    );
  });

  it('3. Migration 0005 defines views, append-only AuditLog trigger, and stored function compatible with appendAuditEvent', () => {
    const sql0005 = fs.readFileSync(MIGRATION_0005_PATH, 'utf8');

    // Two required views
    assert.match(sql0005, /CREATE OR REPLACE VIEW "vw_device_security_posture" AS/);
    assert.match(sql0005, /CREATE OR REPLACE VIEW "vw_command_audit_history" AS/);

    // Immutability trigger on AuditLog
    assert.match(sql0005, /CREATE OR REPLACE FUNCTION "fn_prevent_audit_log_mutation"\(\)/);
    assert.match(sql0005, /CREATE TRIGGER "trg_prevent_audit_log_mutation"/);
    assert.match(sql0005, /BEFORE UPDATE OR DELETE ON "AuditLog"/);

    // Stored function for atomic command result recording
    assert.match(sql0005, /CREATE OR REPLACE FUNCTION "fn_record_command_execution_result"\(/);

    // Verify repository.ts never runs auditLog.update or auditLog.delete (trigger compatibility)
    const repoSource = fs.readFileSync(
      path.join(ROOT_DIR, 'src', 'server', 'db', 'repository.ts'),
      'utf8'
    );
    assert.equal(
      /auditLog\.(update|updateMany|delete|deleteMany|upsert)\b/.test(repoSource),
      false,
      'Repository must never execute UPDATE or DELETE on AuditLog'
    );
  });

  it('4. Atomic recordCommandExecutionResult transitions RemoteCommand and records CommandResult with idempotent replay', async () => {
    const repo = new InMemoryIdentityRepository();
    const { user } = await repo.createUserWithCredential({
      email: 'atomic-cmd@example.com',
      displayName: 'Atomic Tester',
      passwordHash: 'hash',
    });
    const { device } = await repo.createEnrollmentPendingDevice({
      userId: user.id,
      name: 'ASUS TUF F16',
      deviceType: 'WINDOWS',
      tokenHash: 'tok-hash-1',
      nonce: 'nonce-1',
      expiresAt: new Date(Date.now() + 600_000),
    });

    const command = await repo.createRemoteCommand({
      deviceId: device.id,
      issuerUserId: user.id,
      actionType: 'LOCK_DEVICE',
      status: 'ACKNOWLEDGED',
      statusMessage: 'Acknowledged by device',
    });

    const firstOutcome = await repo.recordCommandExecutionResult({
      commandId: command.id,
      deviceId: device.id,
      status: 'COMPLETED',
      safeMessage: 'Workstation screen locked immediately.',
      resultMetadata: { sessionLocked: true },
    });

    assert.equal(firstOutcome.idempotentReplay, false);
    assert.equal(firstOutcome.command.status, 'COMPLETED');
    assert.equal(firstOutcome.result.status, 'COMPLETED');
    assert.equal(firstOutcome.result.safeMessage, 'Workstation screen locked immediately.');

    // Second submission for the same commandId must return idempotentReplay: true without throwing
    const replayOutcome = await repo.recordCommandExecutionResult({
      commandId: command.id,
      deviceId: device.id,
      status: 'COMPLETED',
      safeMessage: 'Duplicate submission',
    });

    assert.equal(replayOutcome.idempotentReplay, true);
    assert.equal(replayOutcome.result.id, firstOutcome.result.id);
    assert.equal(replayOutcome.command.status, 'COMPLETED');

    // Verify sql-evidence.md documentation exists and documents views, trigger, and transactions
    assert.ok(fs.existsSync(SQL_EVIDENCE_DOC_PATH), 'docs/architecture/sql-evidence.md must exist');
    const docContent = fs.readFileSync(SQL_EVIDENCE_DOC_PATH, 'utf8');
    assert.match(docContent, /vw_device_security_posture/);
    assert.match(docContent, /vw_command_audit_history/);
    assert.match(docContent, /trg_prevent_audit_log_mutation/);
    assert.match(docContent, /fn_record_command_execution_result/);
  });
});
