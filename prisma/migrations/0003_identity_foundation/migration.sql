-- VAJRA — Migration 0003_identity_foundation
-- Provider: PostgreSQL

-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'LOCKED', 'DISABLED');

-- CreateEnum
CREATE TYPE "DeviceType" AS ENUM ('WINDOWS', 'ANDROID', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "DeviceLifecycleState" AS ENUM ('UNREGISTERED', 'ENROLLMENT_PENDING', 'TRUSTED', 'ACTIVE', 'OFFLINE', 'LOST', 'COMPROMISED', 'REVOKED', 'DECOMMISSIONED');

-- CreateEnum
CREATE TYPE "DeviceConnectivityStatus" AS ENUM ('ONLINE', 'OFFLINE', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "RiskLevel" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "KeyAlgorithm" AS ENUM ('ED25519', 'ECDSA_P256');

-- CreateEnum
CREATE TYPE "SessionType" AS ENUM ('WEB_CONSOLE', 'DEVICE_STREAM');

-- CreateTable
CREATE TABLE "User" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "status" "UserStatus" NOT NULL DEFAULT 'ACTIVE',
    "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserCredential" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "totpSecretEncrypted" TEXT,
    "totpEnabled" BOOLEAN NOT NULL DEFAULT false,
    "recoveryCodeHashes" JSONB NOT NULL DEFAULT '[]',
    "passwordChangedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PasskeyCredential" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKeyBase64" TEXT NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT[],
    "label" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "PasskeyCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Device" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "deviceType" "DeviceType" NOT NULL,
    "lifecycleState" "DeviceLifecycleState" NOT NULL DEFAULT 'ENROLLMENT_PENDING',
    "connectivityStatus" "DeviceConnectivityStatus" NOT NULL DEFAULT 'UNKNOWN',
    "osVersion" TEXT,
    "agentVersion" TEXT,
    "currentRiskScore" INTEGER NOT NULL DEFAULT 0,
    "currentRiskLevel" "RiskLevel" NOT NULL DEFAULT 'LOW',
    "lastHeartbeatAt" TIMESTAMP(3),
    "enrolledAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceCredential" (
    "id" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "keyAlgorithm" "KeyAlgorithm" NOT NULL DEFAULT 'ED25519',
    "publicKeyPem" TEXT NOT NULL,
    "publicKeyFingerprint" TEXT NOT NULL,
    "hardwareBacked" BOOLEAN NOT NULL DEFAULT false,
    "enrollmentTokenHash" TEXT,
    "enrollmentExpiresAt" TIMESTAMP(3),
    "active" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confirmedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "DeviceCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceSession" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "deviceId" UUID,
    "sessionType" "SessionType" NOT NULL DEFAULT 'WEB_CONSOLE',
    "tokenHash" TEXT NOT NULL,
    "csrfTokenHash" TEXT NOT NULL,
    "mfaVerified" BOOLEAN NOT NULL DEFAULT false,
    "mfaVerifiedAt" TIMESTAMP(3),
    "stepUpVerifiedUntil" TIMESTAMP(3),
    "ipAddressTruncated" TEXT,
    "userAgentSummary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastActiveAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "absoluteExpiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "DeviceSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" UUID NOT NULL,
    "sequenceNumber" SERIAL NOT NULL,
    "actorUserId" UUID,
    "actorDeviceId" UUID,
    "eventType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "previousEntryHash" TEXT NOT NULL,
    "entryHash" TEXT NOT NULL,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_status_idx" ON "User"("status");

-- CreateIndex
CREATE UNIQUE INDEX "UserCredential_userId_key" ON "UserCredential"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "PasskeyCredential_credentialId_key" ON "PasskeyCredential"("credentialId");

-- CreateIndex
CREATE INDEX "PasskeyCredential_userId_idx" ON "PasskeyCredential"("userId");

-- CreateIndex
CREATE INDEX "Device_userId_idx" ON "Device"("userId");

-- CreateIndex
CREATE INDEX "Device_lifecycleState_idx" ON "Device"("lifecycleState");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceCredential_publicKeyFingerprint_key" ON "DeviceCredential"("publicKeyFingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceCredential_enrollmentTokenHash_key" ON "DeviceCredential"("enrollmentTokenHash");

-- CreateIndex
CREATE INDEX "DeviceCredential_deviceId_idx" ON "DeviceCredential"("deviceId");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceSession_tokenHash_key" ON "DeviceSession"("tokenHash");

-- CreateIndex
CREATE INDEX "DeviceSession_userId_idx" ON "DeviceSession"("userId");

-- CreateIndex
CREATE INDEX "DeviceSession_tokenHash_idx" ON "DeviceSession"("tokenHash");

-- CreateIndex
CREATE INDEX "DeviceSession_expiresAt_idx" ON "DeviceSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuditLog_sequenceNumber_key" ON "AuditLog"("sequenceNumber");

-- CreateIndex
CREATE UNIQUE INDEX "AuditLog_entryHash_key" ON "AuditLog"("entryHash");

-- CreateIndex
CREATE INDEX "AuditLog_actorUserId_idx" ON "AuditLog"("actorUserId");

-- CreateIndex
CREATE INDEX "AuditLog_eventType_idx" ON "AuditLog"("eventType");

-- CreateIndex
CREATE INDEX "AuditLog_timestamp_idx" ON "AuditLog"("timestamp");

-- AddForeignKey
ALTER TABLE "UserCredential" ADD CONSTRAINT "UserCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PasskeyCredential" ADD CONSTRAINT "PasskeyCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceCredential" ADD CONSTRAINT "DeviceCredential_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceSession" ADD CONSTRAINT "DeviceSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceSession" ADD CONSTRAINT "DeviceSession_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorDeviceId_fkey" FOREIGN KEY ("actorDeviceId") REFERENCES "Device"("id") ON DELETE SET NULL ON UPDATE CASCADE;
