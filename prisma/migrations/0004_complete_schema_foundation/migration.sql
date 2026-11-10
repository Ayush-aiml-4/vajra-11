-- VAJRA — Migration 0004_complete_schema_foundation
-- Provider: PostgreSQL
-- Purpose: Forward-only migration reconciling prisma/schema.prisma with 0003_identity_foundation.
-- Adds missing enums, Device/DeviceCredential columns, and all remaining tables, indexes,
-- foreign keys, and validated CHECK constraints on risk scores and telemetry ranges.

-- CreateEnum
CREATE TYPE "DeviceCredentialStatus" AS ENUM ('PENDING_CONFIRMATION', 'ACTIVE', 'ROTATED', 'REVOKED');

-- AlterTable: Device (add missing columns from Prompt 0004–0008)
ALTER TABLE "Device" ADD COLUMN "lastSeenAt" TIMESTAMP(3),
ADD COLUMN "compromisedAt" TIMESTAMP(3);

-- AlterTable: DeviceCredential (add missing columns from Prompt 0004)
ALTER TABLE "DeviceCredential" ADD COLUMN "status" "DeviceCredentialStatus" NOT NULL DEFAULT 'PENDING_CONFIRMATION',
ADD COLUMN "rotatedAt" TIMESTAMP(3);

-- CreateTable: EnrollmentChallenge
CREATE TABLE "EnrollmentChallenge" (
    "id" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "purpose" TEXT NOT NULL DEFAULT 'DEVICE_ENROLLMENT',
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "proofVerifiedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "EnrollmentChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable: DeviceAuthNonce
CREATE TABLE "DeviceAuthNonce" (
    "id" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DeviceAuthNonce_pkey" PRIMARY KEY ("id")
);

-- CreateTable: Notification
CREATE TABLE "Notification" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "category" TEXT NOT NULL DEFAULT 'Security',
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "readAt" TIMESTAMP(3),
    "dismissedAt" TIMESTAMP(3),
    "relatedDeviceId" UUID,
    "relatedDeviceName" TEXT,
    "relatedEventId" TEXT,
    "actionLabel" TEXT,
    "actionTarget" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable: RemoteCommand
CREATE TABLE "RemoteCommand" (
    "id" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "issuerUserId" UUID NOT NULL,
    "actionType" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "statusMessage" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "payloadSummary" JSONB NOT NULL DEFAULT '{}',
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deliveredAt" TIMESTAMP(3),
    "acknowledgedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "RemoteCommand_pkey" PRIMARY KEY ("id")
);

-- CreateTable: CommandResult
CREATE TABLE "CommandResult" (
    "id" UUID NOT NULL,
    "commandId" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "errorCode" TEXT,
    "safeMessage" TEXT NOT NULL,
    "deviceTimestamp" TIMESTAMP(3),
    "resultMetadata" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "CommandResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable: SecurityEvent
CREATE TABLE "SecurityEvent" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "deviceId" UUID,
    "category" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "source" TEXT NOT NULL DEFAULT 'WEB',
    "correlationId" TEXT,

    CONSTRAINT "SecurityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable: DeviceHeartbeat
CREATE TABLE "DeviceHeartbeat" (
    "id" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "connectivityStatus" TEXT NOT NULL DEFAULT 'ONLINE',
    "batteryLevel" INTEGER,
    "charging" BOOLEAN,
    "networkType" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "osVersion" TEXT,
    "agentVersion" TEXT,
    "permissionSummary" TEXT,
    "securitySummary" TEXT,
    "locationPermissionGranted" BOOLEAN,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeviceHeartbeat_pkey" PRIMARY KEY ("id")
);

-- CreateTable: RiskAssessment
CREATE TABLE "RiskAssessment" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "deviceId" UUID,
    "score" INTEGER NOT NULL,
    "status" TEXT NOT NULL,
    "factors" JSONB NOT NULL DEFAULT '[]',
    "recommendations" JSONB NOT NULL DEFAULT '[]',
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable: ThreatCheck
CREATE TABLE "ThreatCheck" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "deviceId" UUID,
    "submittedUrl" TEXT NOT NULL,
    "normalizedDomain" TEXT NOT NULL,
    "verdict" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "summary" TEXT NOT NULL,
    "recommendedGuidance" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'WEB',
    "checkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ThreatCheck_pkey" PRIMARY KEY ("id")
);

-- CreateTable: ThreatIndicator
CREATE TABLE "ThreatIndicator" (
    "id" UUID NOT NULL,
    "threatCheckId" UUID NOT NULL,
    "code" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "explanation" TEXT NOT NULL,
    "weight" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ThreatIndicator_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DeviceCredential_status_idx" ON "DeviceCredential"("status");

-- CreateIndex
CREATE UNIQUE INDEX "EnrollmentChallenge_tokenHash_key" ON "EnrollmentChallenge"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "EnrollmentChallenge_nonce_key" ON "EnrollmentChallenge"("nonce");

-- CreateIndex
CREATE INDEX "EnrollmentChallenge_deviceId_idx" ON "EnrollmentChallenge"("deviceId");

-- CreateIndex
CREATE INDEX "EnrollmentChallenge_userId_idx" ON "EnrollmentChallenge"("userId");

-- CreateIndex
CREATE INDEX "EnrollmentChallenge_expiresAt_idx" ON "EnrollmentChallenge"("expiresAt");

-- CreateIndex
CREATE INDEX "DeviceAuthNonce_expiresAt_idx" ON "DeviceAuthNonce"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceAuthNonce_deviceId_nonce_key" ON "DeviceAuthNonce"("deviceId", "nonce");

-- CreateIndex
CREATE INDEX "Notification_userId_idx" ON "Notification"("userId");

-- CreateIndex
CREATE INDEX "Notification_createdAt_idx" ON "Notification"("createdAt");

-- CreateIndex
CREATE INDEX "Notification_readAt_idx" ON "Notification"("readAt");

-- CreateIndex
CREATE INDEX "Notification_severity_idx" ON "Notification"("severity");

-- CreateIndex
CREATE INDEX "RemoteCommand_deviceId_idx" ON "RemoteCommand"("deviceId");

-- CreateIndex
CREATE INDEX "RemoteCommand_issuerUserId_idx" ON "RemoteCommand"("issuerUserId");

-- CreateIndex
CREATE INDEX "RemoteCommand_status_idx" ON "RemoteCommand"("status");

-- CreateIndex
CREATE INDEX "RemoteCommand_requestedAt_idx" ON "RemoteCommand"("requestedAt");

-- CreateIndex
CREATE INDEX "RemoteCommand_expiresAt_idx" ON "RemoteCommand"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "CommandResult_commandId_key" ON "CommandResult"("commandId");

-- CreateIndex
CREATE INDEX "CommandResult_commandId_idx" ON "CommandResult"("commandId");

-- CreateIndex
CREATE INDEX "CommandResult_deviceId_idx" ON "CommandResult"("deviceId");

-- CreateIndex
CREATE INDEX "SecurityEvent_userId_idx" ON "SecurityEvent"("userId");

-- CreateIndex
CREATE INDEX "SecurityEvent_deviceId_idx" ON "SecurityEvent"("deviceId");

-- CreateIndex
CREATE INDEX "SecurityEvent_category_idx" ON "SecurityEvent"("category");

-- CreateIndex
CREATE INDEX "SecurityEvent_type_idx" ON "SecurityEvent"("type");

-- CreateIndex
CREATE INDEX "SecurityEvent_severity_idx" ON "SecurityEvent"("severity");

-- CreateIndex
CREATE INDEX "SecurityEvent_occurredAt_idx" ON "SecurityEvent"("occurredAt");

-- CreateIndex
CREATE INDEX "DeviceHeartbeat_deviceId_idx" ON "DeviceHeartbeat"("deviceId");

-- CreateIndex
CREATE INDEX "DeviceHeartbeat_receivedAt_idx" ON "DeviceHeartbeat"("receivedAt");

-- CreateIndex
CREATE INDEX "RiskAssessment_userId_idx" ON "RiskAssessment"("userId");

-- CreateIndex
CREATE INDEX "RiskAssessment_deviceId_idx" ON "RiskAssessment"("deviceId");

-- CreateIndex
CREATE INDEX "RiskAssessment_updatedAt_idx" ON "RiskAssessment"("updatedAt");

-- CreateIndex
CREATE INDEX "ThreatCheck_userId_idx" ON "ThreatCheck"("userId");

-- CreateIndex
CREATE INDEX "ThreatCheck_deviceId_idx" ON "ThreatCheck"("deviceId");

-- CreateIndex
CREATE INDEX "ThreatCheck_normalizedDomain_idx" ON "ThreatCheck"("normalizedDomain");

-- CreateIndex
CREATE INDEX "ThreatCheck_verdict_idx" ON "ThreatCheck"("verdict");

-- CreateIndex
CREATE INDEX "ThreatCheck_checkedAt_idx" ON "ThreatCheck"("checkedAt");

-- CreateIndex
CREATE INDEX "ThreatIndicator_threatCheckId_idx" ON "ThreatIndicator"("threatCheckId");

-- CreateIndex
CREATE INDEX "ThreatIndicator_code_idx" ON "ThreatIndicator"("code");

-- CreateIndex
CREATE INDEX "ThreatIndicator_severity_idx" ON "ThreatIndicator"("severity");

-- AddForeignKey
ALTER TABLE "EnrollmentChallenge" ADD CONSTRAINT "EnrollmentChallenge_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceAuthNonce" ADD CONSTRAINT "DeviceAuthNonce_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_relatedDeviceId_fkey" FOREIGN KEY ("relatedDeviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RemoteCommand" ADD CONSTRAINT "RemoteCommand_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RemoteCommand" ADD CONSTRAINT "RemoteCommand_issuerUserId_fkey" FOREIGN KEY ("issuerUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CommandResult" ADD CONSTRAINT "CommandResult_commandId_fkey" FOREIGN KEY ("commandId") REFERENCES "RemoteCommand"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CommandResult" ADD CONSTRAINT "CommandResult_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceHeartbeat" ADD CONSTRAINT "DeviceHeartbeat_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskAssessment" ADD CONSTRAINT "RiskAssessment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskAssessment" ADD CONSTRAINT "RiskAssessment_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatCheck" ADD CONSTRAINT "ThreatCheck_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatCheck" ADD CONSTRAINT "ThreatCheck_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatIndicator" ADD CONSTRAINT "ThreatIndicator_threatCheckId_fkey" FOREIGN KEY ("threatCheckId") REFERENCES "ThreatCheck"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddCheckConstraints (Validated domain range constraints)
ALTER TABLE "User" ADD CONSTRAINT "User_failedLoginAttempts_check" CHECK ("failedLoginAttempts" >= 0);

ALTER TABLE "Device" ADD CONSTRAINT "Device_currentRiskScore_check" CHECK ("currentRiskScore" >= 0 AND "currentRiskScore" <= 100);

ALTER TABLE "DeviceHeartbeat" ADD CONSTRAINT "DeviceHeartbeat_batteryLevel_check" CHECK ("batteryLevel" IS NULL OR ("batteryLevel" >= 0 AND "batteryLevel" <= 100));

ALTER TABLE "RiskAssessment" ADD CONSTRAINT "RiskAssessment_score_check" CHECK ("score" >= 0 AND "score" <= 100);

ALTER TABLE "ThreatCheck" ADD CONSTRAINT "ThreatCheck_riskScore_check" CHECK ("riskScore" >= 0 AND "riskScore" <= 100);

ALTER TABLE "ThreatIndicator" ADD CONSTRAINT "ThreatIndicator_weight_check" CHECK ("weight" >= 0 AND "weight" <= 100);
