/**
 * VAJRA — Identity & Authentication Repository Layer
 * Prompt 0003: PostgreSQL + Prisma + Secure Authentication Foundation
 *
 * Uses Prisma Client against PostgreSQL when DATABASE_URL points to a live database,
 * and supports a clean, deterministic in-memory adapter for unit/integration testing
 * or sandboxed preview environments when PostgreSQL is not reachable.
 */

import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  StoredRecoveryCodeRecord,
  verifyAndConsumeRecoveryCode,
  AuditChainEntry,
  AUDIT_GENESIS_PREVIOUS_HASH,
  computeAuditEntryHash,
  sanitizeLogMetadata,
} from '../../../packages/security/src/node.ts';

export type AccountStatus = 'ACTIVE' | 'LOCKED' | 'DISABLED';

export interface UserEntity {
  id: string;
  email: string;
  displayName: string;
  status: AccountStatus;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserCredentialEntity {
  id: string;
  userId: string;
  passwordHash: string;
  totpSecretEncrypted: string | null;
  totpEnabled: boolean;
  recoveryCodeHashes: StoredRecoveryCodeRecord[];
  passwordChangedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeviceSessionEntity {
  id: string;
  userId: string;
  deviceId: string | null;
  sessionType: 'WEB_CONSOLE' | 'DEVICE_STREAM';
  tokenHash: string;
  csrfTokenHash: string;
  mfaVerified: boolean;
  mfaVerifiedAt: Date | null;
  stepUpVerifiedUntil: Date | null;
  stepUpActionScope: string | null;
  ipAddressTruncated: string | null;
  userAgentSummary: string | null;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  revokedAt: Date | null;
}

export type DeviceTypeEntity = 'WINDOWS' | 'ANDROID' | 'UNKNOWN';
export type DeviceLifecycleStateEntity =
  | 'UNREGISTERED'
  | 'ENROLLMENT_PENDING'
  | 'TRUSTED'
  | 'ACTIVE'
  | 'OFFLINE'
  | 'LOST'
  | 'COMPROMISED'
  | 'REVOKED'
  | 'DECOMMISSIONED';
export type DeviceConnectivityStatusEntity = 'ONLINE' | 'OFFLINE' | 'UNKNOWN';
export type RiskLevelEntity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type KeyAlgorithmEntity = 'ED25519' | 'ECDSA_P256';
export type DeviceCredentialStatusEntity =
  | 'PENDING_CONFIRMATION'
  | 'ACTIVE'
  | 'ROTATED'
  | 'REVOKED';

export interface DeviceEntity {
  id: string;
  userId: string;
  name: string;
  deviceType: DeviceTypeEntity;
  lifecycleState: DeviceLifecycleStateEntity;
  connectivityStatus: DeviceConnectivityStatusEntity;
  osVersion: string | null;
  agentVersion: string | null;
  currentRiskScore: number;
  currentRiskLevel: RiskLevelEntity;
  lastHeartbeatAt: Date | null;
  lastSeenAt: Date | null;
  enrolledAt: Date | null;
  revokedAt: Date | null;
  compromisedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeviceCredentialEntity {
  id: string;
  deviceId: string;
  keyAlgorithm: KeyAlgorithmEntity;
  publicKeyPem: string;
  publicKeyFingerprint: string;
  status: DeviceCredentialStatusEntity;
  hardwareBacked: boolean;
  enrollmentTokenHash: string | null;
  enrollmentExpiresAt: Date | null;
  active: boolean;
  createdAt: Date;
  confirmedAt: Date | null;
  rotatedAt: Date | null;
  revokedAt: Date | null;
}

export interface EnrollmentChallengeEntity {
  id: string;
  deviceId: string;
  userId: string;
  tokenHash: string;
  nonce: string;
  passcodeHash?: string | null;
  failedAttempts?: number;
  purpose: string;
  issuedAt: Date;
  expiresAt: Date;
  proofVerifiedAt: Date | null;
  consumedAt: Date | null;
}

export interface DeviceAuthNonceEntity {
  id: string;
  deviceId: string;
  nonce: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface NotificationEntity {
  id: string;
  userId: string;
  type: string;
  severity: string;
  category: string;
  title: string;
  message: string;
  createdAt: Date;
  readAt: Date | null;
  dismissedAt: Date | null;
  relatedDeviceId: string | null;
  relatedDeviceName: string | null;
  relatedEventId: string | null;
  actionLabel: string | null;
  actionTarget: string | null;
  metadata: Record<string, unknown>;
}

export interface RemoteCommandEntity {
  id: string;
  deviceId: string;
  issuerUserId: string;
  actionType: string;
  status: string;
  statusMessage: string;
  nonce?: string;
  payloadSummary: Record<string, unknown>;
  requestedAt: Date;
  deliveredAt?: Date | null;
  acknowledgedAt?: Date | null;
  completedAt: Date | null;
  expiresAt?: Date | null;
}

export interface CommandResultEntity {
  id: string;
  commandId: string;
  deviceId: string;
  status: 'COMPLETED' | 'FAILED' | string;
  receivedAt: Date;
  completedAt: Date | null;
  errorCode: string | null;
  safeMessage: string;
  deviceTimestamp: Date | null;
  resultMetadata?: Record<string, unknown>;
}

/** Terminal command statuses that must never be overwritten by later receipts. */
export const TERMINAL_COMMAND_STATUSES = new Set([
  'COMPLETED',
  'FAILED',
  'EXPIRED',
  'CANCELLED',
  'REJECTED',
]);

/**
 * Legal remote-command state transitions (Prompt 0011D).
 * QUEUED/PENDING → DELIVERED → ACKNOWLEDGED → COMPLETED|FAILED
 * Cancellation and expiry only from non-terminal pre-completion states.
 */
export const LEGAL_COMMAND_TRANSITIONS: Record<string, ReadonlySet<string>> = {
  PENDING: new Set(['QUEUED', 'DELIVERED', 'ACKNOWLEDGED', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED']),
  QUEUED: new Set(['DELIVERED', 'ACKNOWLEDGED', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED']),
  DELIVERED: new Set(['ACKNOWLEDGED', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED']),
  ACKNOWLEDGED: new Set(['COMPLETED', 'FAILED', 'EXPIRED']),
  COMPLETED: new Set(),
  FAILED: new Set(),
  EXPIRED: new Set(),
  CANCELLED: new Set(),
  REJECTED: new Set(),
};

export function isLegalCommandTransition(from: string, to: string): boolean {
  if (from === to) return true;
  const allowed = LEGAL_COMMAND_TRANSITIONS[from];
  if (!allowed) return false;
  return allowed.has(to);
}

export interface SecurityEventEntity {
  id: string;
  userId: string;
  deviceId: string | null;
  category: string;
  type: string;
  severity: string;
  occurredAt: Date;
  receivedAt: Date;
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  source: string;
  correlationId: string | null;
}

export interface DeviceHeartbeatEntity {
  id: string;
  deviceId: string;
  connectivityStatus: 'ONLINE' | 'OFFLINE';
  batteryLevel: number | null;
  charging: boolean | null;
  networkType: 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN';
  osVersion: string | null;
  agentVersion: string | null;
  permissionSummary: string | null;
  securitySummary: string | null;
  locationPermissionGranted: boolean | null;
  receivedAt: Date;
}

export interface RiskAssessmentEntity {
  id: string;
  userId: string;
  deviceId: string | null;
  score: number;
  status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
  factors: string[];
  recommendations: string[];
  updatedAt: Date;
}

export interface ThreatIndicatorEntity {
  id: string;
  threatCheckId: string;
  code: string;
  category: string;
  severity: string;
  title: string;
  explanation: string;
  weight: number;
  createdAt: Date;
}

export interface ThreatCheckEntity {
  id: string;
  userId: string;
  deviceId: string | null;
  submittedUrl: string;
  normalizedDomain: string;
  verdict: string;
  riskScore: number;
  summary: string;
  recommendedGuidance: string;
  source: string;
  checkedAt: Date;
  indicators: ThreatIndicatorEntity[];
}

export interface IdentityRepository {
  readonly backendType: 'POSTGRESQL_PRISMA' | 'MEMORY_FALLBACK';

  /**
   * Bounded readiness probe for the identity store.
   * Must not throw secrets or connection strings.
   */
  checkDatabaseHealth(timeoutMs?: number): Promise<{
    ok: boolean;
    backend: 'POSTGRESQL_PRISMA' | 'MEMORY_FALLBACK';
    latencyMs?: number;
    errorCode?: string;
  }>;

  // User & Credential operations
  findUserByEmail(email: string): Promise<UserEntity | null>;
  findUserById(userId: string): Promise<UserEntity | null>;
  findCredentialByUserId(userId: string): Promise<UserCredentialEntity | null>;
  createUserWithCredential(params: {
    email: string;
    displayName: string;
    passwordHash: string;
  }): Promise<{ user: UserEntity; credential: UserCredentialEntity }>;
  updateUserLoginState(params: {
    userId: string;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    lastLoginAt?: Date;
    status?: AccountStatus;
  }): Promise<UserEntity>;
  updateUserCredential(params: {
    userId: string;
    passwordHash?: string;
    totpSecretEncrypted?: string | null;
    totpEnabled?: boolean;
    recoveryCodeHashes?: StoredRecoveryCodeRecord[];
    passwordChangedAt?: Date;
  }): Promise<UserCredentialEntity>;
  /** Atomically verifies and marks a single-use recovery code as used, preventing concurrent reuse. */
  consumeRecoveryCodeAtomically(params: {
    userId: string;
    rawRecoveryCode: string;
    usedAtIso: string;
  }): Promise<{ valid: boolean; consumedCodeId?: string }>;

  // Session operations
  createSession(params: {
    userId: string;
    tokenHash: string;
    csrfTokenHash: string;
    mfaVerified: boolean;
    mfaVerifiedAt: Date | null;
    stepUpVerifiedUntil: Date | null;
    stepUpActionScope?: string | null;
    ipAddressTruncated: string | null;
    userAgentSummary: string | null;
    expiresAt: Date;
    absoluteExpiresAt: Date;
  }): Promise<DeviceSessionEntity>;
  findSessionByTokenHash(tokenHash: string): Promise<DeviceSessionEntity | null>;
  updateSessionActivityAndRotation(params: {
    sessionId: string;
    newTokenHash?: string;
    newCsrfTokenHash?: string;
    stepUpVerifiedUntil?: Date | null;
    stepUpActionScope?: string | null;
    lastActiveAt: Date;
    expiresAt: Date;
  }): Promise<DeviceSessionEntity>;
  /** Explicit step-up grant: sets stepUpVerifiedUntil + action scope on the session. */
  grantStepUp(params: {
    sessionId: string;
    stepUpVerifiedUntil: Date;
    stepUpActionScope: string;
  }): Promise<DeviceSessionEntity>;
  /** Atomically consumes a non-expired, scope-matching step-up grant; returns true iff this caller won the single-use grant. */
  consumeStepUp(params: {
    sessionId: string;
    acceptableScopes: string[];
    now?: Date;
  }): Promise<boolean>;
  /** Clears step-up after a sensitive action is consumed (one-shot scope) or on expiry. */
  clearStepUp(sessionId: string): Promise<DeviceSessionEntity | null>;
  revokeSessionById(sessionId: string, revokedAt?: Date): Promise<void>;
  revokeUserSessionById(params: {
    userId: string;
    sessionId: string;
    revokedAt?: Date;
  }): Promise<boolean>;
  listActiveUserSessions(userId: string, now?: Date): Promise<DeviceSessionEntity[]>;
  revokeAllUserSessions(userId: string, exceptSessionId?: string): Promise<number>;

  // Device, EnrollmentChallenge & Cryptographic DeviceCredential operations (Prompt 0004)
  createEnrollmentPendingDevice(params: {
    userId: string;
    name: string;
    deviceType: DeviceTypeEntity;
    tokenHash: string;
    nonce: string;
    passcodeHash?: string | null;
    expiresAt: Date;
  }): Promise<{ device: DeviceEntity; challenge: EnrollmentChallengeEntity }>;
  recordFailedEnrollmentChallengeAttemptAtomic(
    challengeId: string,
    maxAttempts?: number,
    now?: Date
  ): Promise<{
    allowed: boolean;
    failedAttempts: number;
    locked: boolean;
    reason?: 'LOCKED' | 'ALREADY_CONSUMED' | 'EXPIRED' | 'NOT_FOUND';
  }>;
  findEnrollmentChallengeByTokenHash(tokenHash: string): Promise<EnrollmentChallengeEntity | null>;
  findDeviceById(deviceId: string): Promise<DeviceEntity | null>;
  listDevicesByUserId(
    userId: string,
    options?: { includeDecommissioned?: boolean }
  ): Promise<Array<{ device: DeviceEntity; credentials: DeviceCredentialEntity[] }>>;
  findCredentialByFingerprint(fingerprint: string): Promise<DeviceCredentialEntity | null>;
  listCredentialsByDeviceId(deviceId: string): Promise<DeviceCredentialEntity[]>;
  submitDevicePublicKey(params: {
    challengeId: string;
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    reportedName?: string | null;
    osVersion: string | null;
    agentVersion: string | null;
    tokenHash: string;
    enrollmentExpiresAt: Date;
    verifiedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity; challenge: EnrollmentChallengeEntity }>;
  confirmDeviceEnrollment(params: {
    deviceId: string;
    confirmedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity }>;
  rejectDeviceEnrollment(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity | null }>;
  listPendingApprovalDevices(userId: string): Promise<
    Array<{ device: DeviceEntity; credential: DeviceCredentialEntity }>
  >;
  rotateDeviceCredential(params: {
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    rotatedAt: Date;
  }): Promise<{ device: DeviceEntity; activeCredential: DeviceCredentialEntity }>;
  updateDeviceState(params: {
    deviceId: string;
    lifecycleState: DeviceLifecycleStateEntity;
    name?: string;
    connectivityStatus?: DeviceConnectivityStatusEntity;
    lastSeenAt?: Date;
    lastHeartbeatAt?: Date;
    osVersion?: string | null;
    agentVersion?: string | null;
    currentRiskScore?: number;
    currentRiskLevel?: RiskLevelEntity;
    revokedAt?: Date | null;
    compromisedAt?: Date | null;
  }): Promise<DeviceEntity>;
  revokeDeviceAndCredentials(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<DeviceEntity>;
  consumeDeviceAuthNonce(params: {
    deviceId: string;
    nonce: string;
    expiresAt: Date;
    now?: Date;
  }): Promise<boolean>;

  // Hash-chained AuditLog operations
  appendAuditEvent(params: {
    actorUserId: string | null;
    actorDeviceId?: string | null;
    eventType: string;
    metadata?: Record<string, unknown>;
    timestamp?: Date;
  }): Promise<AuditChainEntry>;
  listAuditEvents(params?: {
    actorUserId?: string;
    actorDeviceId?: string;
    limit?: number;
  }): Promise<AuditChainEntry[]>;
  getAllAuditEventsOrdered(): Promise<AuditChainEntry[]>;

  // Notification operations (Prompt 0007)
  createNotification(params: {
    userId: string;
    type: string;
    severity: string;
    category?: string;
    title: string;
    message: string;
    relatedDeviceId?: string | null;
    relatedDeviceName?: string | null;
    relatedEventId?: string | null;
    actionLabel?: string | null;
    actionTarget?: string | null;
    metadata?: Record<string, unknown>;
    createdAt?: Date;
  }): Promise<NotificationEntity>;
  listNotificationsByUserId(
    userId: string,
    options?: { includeDismissed?: boolean; limit?: number }
  ): Promise<NotificationEntity[]>;
  markNotificationRead(params: {
    notificationId: string;
    userId: string;
    readAt?: Date;
  }): Promise<NotificationEntity | null>;
  markAllNotificationsRead(params: {
    userId: string;
    readAt?: Date;
  }): Promise<number>;
  dismissNotification(params: {
    notificationId: string;
    userId: string;
    dismissedAt?: Date;
  }): Promise<NotificationEntity | null>;

  // RemoteCommand / Device Action operations (Prompts 0007 & 0008)
  createRemoteCommand(params: {
    deviceId: string;
    issuerUserId: string;
    actionType: string;
    status: string;
    statusMessage: string;
    nonce?: string;
    payloadSummary?: Record<string, unknown>;
    requestedAt?: Date;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
    expiresAt?: Date | null;
  }): Promise<RemoteCommandEntity>;
  findRemoteCommandById(commandId: string): Promise<RemoteCommandEntity | null>;
  listRemoteCommandsByDeviceId(
    deviceId: string,
    userId: string,
    limit?: number
  ): Promise<RemoteCommandEntity[]>;
  listPendingCommandsForDevice(deviceId: string): Promise<RemoteCommandEntity[]>;
  updateRemoteCommandState(params: {
    commandId: string;
    status: string;
    statusMessage?: string;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
  }): Promise<RemoteCommandEntity>;
  expireStaleRemoteCommands(params: {
    deviceId: string;
    now?: Date;
  }): Promise<RemoteCommandEntity[]>;
  createCommandResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED' | string;
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<CommandResultEntity>;
  recordCommandExecutionResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED';
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<{
    command: RemoteCommandEntity;
    result: CommandResultEntity;
    idempotentReplay: boolean;
  }>;
  findCommandResultByCommandId(commandId: string): Promise<CommandResultEntity | null>;

  // SecurityEvent operations (Prompt 0008)
  createSecurityEvent(params: {
    userId: string;
    deviceId?: string | null;
    category: string;
    type: string;
    severity: string;
    occurredAt?: Date;
    receivedAt?: Date;
    title: string;
    description: string;
    metadata?: Record<string, unknown>;
    source?: string;
    correlationId?: string | null;
  }): Promise<SecurityEventEntity>;
  listSecurityEventsByUserId(
    userId: string,
    options?: {
      category?: string;
      deviceId?: string;
      severity?: string;
      since?: Date;
      until?: Date;
      limit?: number;
    }
  ): Promise<SecurityEventEntity[]>;

  // DeviceHeartbeat operations (Prompt 0008)
  createDeviceHeartbeat(params: {
    deviceId: string;
    reportedName?: string | null;
    connectivityStatus?: 'ONLINE' | 'OFFLINE';
    batteryLevel?: number | null;
    charging?: boolean | null;
    networkType?: 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN';
    osVersion?: string | null;
    agentVersion?: string | null;
    permissionSummary?: string | null;
    securitySummary?: string | null;
    locationPermissionGranted?: boolean | null;
    receivedAt?: Date;
  }): Promise<DeviceHeartbeatEntity>;
  getLatestDeviceHeartbeat(deviceId: string): Promise<DeviceHeartbeatEntity | null>;
  listDeviceHeartbeats(
    deviceId: string,
    options?: { since?: Date; limit?: number }
  ): Promise<DeviceHeartbeatEntity[]>;

  // RiskAssessment operations (Prompt 0008)
  saveRiskAssessment(params: {
    userId: string;
    deviceId?: string | null;
    score: number;
    status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
    factors: string[];
    recommendations: string[];
    updatedAt?: Date;
  }): Promise<RiskAssessmentEntity>;
  getLatestRiskAssessment(
    userId: string,
    deviceId?: string | null
  ): Promise<RiskAssessmentEntity | null>;

  // ThreatCheck & ThreatIndicator operations (Prompt 0011B)
  createThreatCheck(params: {
    userId: string;
    deviceId?: string | null;
    submittedUrl: string;
    normalizedDomain: string;
    verdict: string;
    riskScore: number;
    summary: string;
    recommendedGuidance: string;
    source?: string;
    checkedAt?: Date;
    indicators: Array<{
      code: string;
      category: string;
      severity: string;
      title: string;
      explanation: string;
      weight: number;
    }>;
  }): Promise<ThreatCheckEntity>;
  listThreatChecksByUserId(
    userId: string,
    options?: {
      deviceId?: string;
      verdict?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ items: ThreatCheckEntity[]; totalCount: number }>;
  listAllRemoteCommandsByUserId(
    userId: string,
    limit?: number
  ): Promise<RemoteCommandEntity[]>;
}

/**
 * Prisma-backed PostgreSQL IdentityRepository implementation.
 */
export class PrismaIdentityRepository implements IdentityRepository {
  public readonly backendType = 'POSTGRESQL_PRISMA' as const;
  private readonly prisma: PrismaClient;

  constructor(prismaClient?: PrismaClient) {
    this.prisma = prismaClient ?? new PrismaClient();
  }

  async checkDatabaseHealth(timeoutMs = 2000): Promise<{
    ok: boolean;
    backend: 'POSTGRESQL_PRISMA' | 'MEMORY_FALLBACK';
    latencyMs?: number;
    errorCode?: string;
  }> {
    const started = Date.now();
    try {
      const timeout = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('DB_HEALTH_TIMEOUT')), timeoutMs);
      });
      await Promise.race([this.prisma.$queryRaw`SELECT 1`, timeout]);
      return {
        ok: true,
        backend: 'POSTGRESQL_PRISMA',
        latencyMs: Date.now() - started,
      };
    } catch {
      return {
        ok: false,
        backend: 'POSTGRESQL_PRISMA',
        latencyMs: Date.now() - started,
        errorCode: 'DATABASE_UNAVAILABLE',
      };
    }
  }

  async findUserByEmail(email: string): Promise<UserEntity | null> {
    const normalized = email.trim().toLowerCase();
    return this.prisma.user.findUnique({ where: { email: normalized } });
  }

  async findUserById(userId: string): Promise<UserEntity | null> {
    return this.prisma.user.findUnique({ where: { id: userId } });
  }

  async findCredentialByUserId(userId: string): Promise<UserCredentialEntity | null> {
    const cred = await this.prisma.userCredential.findUnique({ where: { userId } });
    if (!cred) return null;
    return {
      ...cred,
      recoveryCodeHashes: Array.isArray(cred.recoveryCodeHashes)
        ? (cred.recoveryCodeHashes as unknown as StoredRecoveryCodeRecord[])
        : [],
    };
  }

  async createUserWithCredential(params: {
    email: string;
    displayName: string;
    passwordHash: string;
  }): Promise<{ user: UserEntity; credential: UserCredentialEntity }> {
    const normalizedEmail = params.email.trim().toLowerCase();
    const result = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        displayName: params.displayName.trim(),
        status: 'ACTIVE',
        credential: {
          create: {
            passwordHash: params.passwordHash,
            totpEnabled: false,
            recoveryCodeHashes: [],
          },
        },
      },
      include: { credential: true },
    });

    const credential = result.credential!;
    return {
      user: {
        id: result.id,
        email: result.email,
        displayName: result.displayName,
        status: result.status,
        failedLoginAttempts: result.failedLoginAttempts,
        lockedUntil: result.lockedUntil,
        lastLoginAt: result.lastLoginAt,
        createdAt: result.createdAt,
        updatedAt: result.updatedAt,
      },
      credential: {
        ...credential,
        recoveryCodeHashes: [],
      },
    };
  }

  async updateUserLoginState(params: {
    userId: string;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    lastLoginAt?: Date;
    status?: AccountStatus;
  }): Promise<UserEntity> {
    return this.prisma.user.update({
      where: { id: params.userId },
      data: {
        failedLoginAttempts: params.failedLoginAttempts,
        lockedUntil: params.lockedUntil,
        ...(params.lastLoginAt !== undefined ? { lastLoginAt: params.lastLoginAt } : {}),
        ...(params.status !== undefined ? { status: params.status } : {}),
      },
    });
  }

  async updateUserCredential(params: {
    userId: string;
    passwordHash?: string;
    totpSecretEncrypted?: string | null;
    totpEnabled?: boolean;
    recoveryCodeHashes?: StoredRecoveryCodeRecord[];
    passwordChangedAt?: Date;
  }): Promise<UserCredentialEntity> {
    const updated = await this.prisma.userCredential.update({
      where: { userId: params.userId },
      data: {
        ...(params.passwordHash !== undefined ? { passwordHash: params.passwordHash } : {}),
        ...(params.totpSecretEncrypted !== undefined
          ? { totpSecretEncrypted: params.totpSecretEncrypted }
          : {}),
        ...(params.totpEnabled !== undefined ? { totpEnabled: params.totpEnabled } : {}),
        ...(params.recoveryCodeHashes !== undefined
          ? { recoveryCodeHashes: params.recoveryCodeHashes as unknown as object }
          : {}),
        ...(params.passwordChangedAt !== undefined
          ? { passwordChangedAt: params.passwordChangedAt }
          : {}),
      },
    });

    return {
      ...updated,
      recoveryCodeHashes: Array.isArray(updated.recoveryCodeHashes)
        ? (updated.recoveryCodeHashes as unknown as StoredRecoveryCodeRecord[])
        : [],
    };
  }

  async consumeRecoveryCodeAtomically(params: {
    userId: string;
    rawRecoveryCode: string;
    usedAtIso: string;
  }): Promise<{ valid: boolean; consumedCodeId?: string }> {
    return this.prisma.$transaction(async (tx: any) => {
      const rows = (await tx.$queryRaw`
        SELECT "recoveryCodeHashes"
        FROM "UserCredential"
        WHERE "userId" = ${params.userId}::uuid
        FOR UPDATE
      `) as Array<{ recoveryCodeHashes: unknown }>;

      if (!rows || rows.length === 0) {
        return { valid: false };
      }

      const currentRecords = Array.isArray(rows[0].recoveryCodeHashes)
        ? (rows[0].recoveryCodeHashes as unknown as StoredRecoveryCodeRecord[])
        : [];

      const consumeResult = verifyAndConsumeRecoveryCode(
        params.rawRecoveryCode,
        currentRecords,
        params.usedAtIso
      );

      if (!consumeResult.valid) {
        return { valid: false };
      }

      await tx.userCredential.update({
        where: { userId: params.userId },
        data: {
          recoveryCodeHashes: consumeResult.updatedRecords as unknown as object,
        },
      });

      return {
        valid: true,
        consumedCodeId: consumeResult.consumedCodeId,
      };
    });
  }

  async createSession(params: {
    userId: string;
    tokenHash: string;
    csrfTokenHash: string;
    mfaVerified: boolean;
    mfaVerifiedAt: Date | null;
    stepUpVerifiedUntil: Date | null;
    stepUpActionScope?: string | null;
    ipAddressTruncated: string | null;
    userAgentSummary: string | null;
    expiresAt: Date;
    absoluteExpiresAt: Date;
  }): Promise<DeviceSessionEntity> {
    return this.prisma.deviceSession.create({
      data: {
        userId: params.userId,
        sessionType: 'WEB_CONSOLE',
        tokenHash: params.tokenHash,
        csrfTokenHash: params.csrfTokenHash,
        mfaVerified: params.mfaVerified,
        mfaVerifiedAt: params.mfaVerifiedAt,
        stepUpVerifiedUntil: params.stepUpVerifiedUntil,
        stepUpActionScope: params.stepUpActionScope ?? null,
        ipAddressTruncated: params.ipAddressTruncated,
        userAgentSummary: params.userAgentSummary,
        expiresAt: params.expiresAt,
        absoluteExpiresAt: params.absoluteExpiresAt,
      },
    });
  }

  async findSessionByTokenHash(tokenHash: string): Promise<DeviceSessionEntity | null> {
    return this.prisma.deviceSession.findUnique({ where: { tokenHash } });
  }

  async updateSessionActivityAndRotation(params: {
    sessionId: string;
    newTokenHash?: string;
    newCsrfTokenHash?: string;
    stepUpVerifiedUntil?: Date | null;
    stepUpActionScope?: string | null;
    lastActiveAt: Date;
    expiresAt: Date;
  }): Promise<DeviceSessionEntity> {
    return this.prisma.deviceSession.update({
      where: { id: params.sessionId },
      data: {
        ...(params.newTokenHash ? { tokenHash: params.newTokenHash } : {}),
        ...(params.newCsrfTokenHash ? { csrfTokenHash: params.newCsrfTokenHash } : {}),
        ...(params.stepUpVerifiedUntil !== undefined
          ? { stepUpVerifiedUntil: params.stepUpVerifiedUntil }
          : {}),
        ...(params.stepUpActionScope !== undefined
          ? { stepUpActionScope: params.stepUpActionScope }
          : {}),
        lastActiveAt: params.lastActiveAt,
        expiresAt: params.expiresAt,
      },
    });
  }

  async grantStepUp(params: {
    sessionId: string;
    stepUpVerifiedUntil: Date;
    stepUpActionScope: string;
  }): Promise<DeviceSessionEntity> {
    return this.prisma.deviceSession.update({
      where: { id: params.sessionId },
      data: {
        stepUpVerifiedUntil: params.stepUpVerifiedUntil,
        stepUpActionScope: params.stepUpActionScope,
      },
    });
  }

  async consumeStepUp(params: {
    sessionId: string;
    acceptableScopes: string[];
    now?: Date;
  }): Promise<boolean> {
    const now = params.now ?? new Date();
    const res = await this.prisma.deviceSession.updateMany({
      where: {
        id: params.sessionId,
        revokedAt: null,
        stepUpVerifiedUntil: { gt: now },
        stepUpActionScope: { in: params.acceptableScopes },
      },
      data: {
        stepUpVerifiedUntil: null,
        stepUpActionScope: null,
      },
    });
    return res.count === 1;
  }

  async clearStepUp(sessionId: string): Promise<DeviceSessionEntity | null> {
    try {
      return await this.prisma.deviceSession.update({
        where: { id: sessionId },
        data: {
          stepUpVerifiedUntil: null,
          stepUpActionScope: null,
        },
      });
    } catch {
      return null;
    }
  }

  async revokeSessionById(sessionId: string, revokedAt: Date = new Date()): Promise<void> {
    await this.prisma.deviceSession.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt },
    });
  }

  async revokeUserSessionById(params: {
    userId: string;
    sessionId: string;
    revokedAt?: Date;
  }): Promise<boolean> {
    const res = await this.prisma.deviceSession.updateMany({
      where: {
        id: params.sessionId,
        userId: params.userId,
        revokedAt: null,
      },
      data: {
        revokedAt: params.revokedAt ?? new Date(),
      },
    });
    return res.count > 0;
  }

  async listActiveUserSessions(
    userId: string,
    now: Date = new Date()
  ): Promise<DeviceSessionEntity[]> {
    return this.prisma.deviceSession.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: now },
        absoluteExpiresAt: { gt: now },
      },
      orderBy: { lastActiveAt: 'desc' },
    });
  }

  async revokeAllUserSessions(userId: string, exceptSessionId?: string): Promise<number> {
    const res = await this.prisma.deviceSession.updateMany({
      where: {
        userId,
        revokedAt: null,
        ...(exceptSessionId ? { id: { not: exceptSessionId } } : {}),
      },
      data: { revokedAt: new Date() },
    });
    return res.count;
  }

  async createEnrollmentPendingDevice(params: {
    userId: string;
    name: string;
    deviceType: DeviceTypeEntity;
    tokenHash: string;
    nonce: string;
    passcodeHash?: string | null;
    expiresAt: Date;
  }): Promise<{ device: DeviceEntity; challenge: EnrollmentChallengeEntity }> {
    return this.prisma.$transaction(async (tx: any) => {
      const device = await tx.device.create({
        data: {
          userId: params.userId,
          name: params.name,
          deviceType: params.deviceType,
          lifecycleState: 'ENROLLMENT_PENDING',
          connectivityStatus: 'UNKNOWN',
        },
      });

      const challenge = await tx.enrollmentChallenge.create({
        data: {
          deviceId: device.id,
          userId: params.userId,
          tokenHash: params.tokenHash,
          nonce: params.nonce,
          passcodeHash: params.passcodeHash ?? null,
          failedAttempts: 0,
          purpose: 'DEVICE_ENROLLMENT',
          expiresAt: params.expiresAt,
        },
      });

      return { device, challenge };
    });
  }

  async recordFailedEnrollmentChallengeAttempt(challengeId: string): Promise<number> {
    const updated = await this.prisma.enrollmentChallenge.update({
      where: { id: challengeId },
      data: { failedAttempts: { increment: 1 } },
      select: { failedAttempts: true },
    });
    return updated.failedAttempts;
  }

  async recordFailedEnrollmentChallengeAttemptAtomic(
    challengeId: string,
    maxAttempts = 5,
    now = new Date()
  ): Promise<{
    allowed: boolean;
    failedAttempts: number;
    locked: boolean;
    reason?: 'LOCKED' | 'ALREADY_CONSUMED' | 'EXPIRED' | 'NOT_FOUND';
  }> {
    const rows = (await this.prisma.$queryRaw`
      UPDATE "EnrollmentChallenge"
      SET "failedAttempts" = "failedAttempts" + 1
      WHERE "id" = ${challengeId}::uuid
        AND "consumedAt" IS NULL
        AND "expiresAt" > ${now}
        AND "failedAttempts" < ${maxAttempts}
      RETURNING "failedAttempts"
    `) as Array<{ failedAttempts: number }>;

    if (!rows || rows.length === 0) {
      const challenge = await this.prisma.enrollmentChallenge.findUnique({
        where: { id: challengeId },
        select: { failedAttempts: true, consumedAt: true, expiresAt: true },
      });
      if (!challenge) {
        return { allowed: false, failedAttempts: maxAttempts, locked: true, reason: 'NOT_FOUND' };
      }
      if (challenge.consumedAt !== null) {
        return { allowed: false, failedAttempts: challenge.failedAttempts ?? 0, locked: false, reason: 'ALREADY_CONSUMED' };
      }
      if (challenge.expiresAt.getTime() <= now.getTime()) {
        return { allowed: false, failedAttempts: challenge.failedAttempts ?? 0, locked: false, reason: 'EXPIRED' };
      }
      return { allowed: false, failedAttempts: challenge.failedAttempts ?? maxAttempts, locked: true, reason: 'LOCKED' };
    }

    const updated = rows[0].failedAttempts;
    const locked = updated >= maxAttempts;
    return {
      allowed: !locked,
      failedAttempts: updated,
      locked,
    };
  }

  async findEnrollmentChallengeByTokenHash(
    tokenHash: string
  ): Promise<EnrollmentChallengeEntity | null> {
    return this.prisma.enrollmentChallenge.findUnique({ where: { tokenHash } });
  }

  async findDeviceById(deviceId: string): Promise<DeviceEntity | null> {
    return this.prisma.device.findUnique({ where: { id: deviceId } });
  }

  async listDevicesByUserId(
    userId: string,
    options?: { includeDecommissioned?: boolean }
  ): Promise<Array<{ device: DeviceEntity; credentials: DeviceCredentialEntity[] }>> {
    const rows = await this.prisma.device.findMany({
      where: {
        userId,
        ...(options?.includeDecommissioned
          ? {}
          : { lifecycleState: { not: 'DECOMMISSIONED' } }),
      },
      include: {
        credentials: {
          orderBy: { createdAt: 'desc' },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return rows.map((r: any) => {
      const { credentials, ...device } = r;
      return { device, credentials };
    });
  }

  async findCredentialByFingerprint(fingerprint: string): Promise<DeviceCredentialEntity | null> {
    return this.prisma.deviceCredential.findUnique({
      where: { publicKeyFingerprint: fingerprint },
    });
  }

  async listCredentialsByDeviceId(deviceId: string): Promise<DeviceCredentialEntity[]> {
    return this.prisma.deviceCredential.findMany({
      where: { deviceId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async submitDevicePublicKey(params: {
    challengeId: string;
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    reportedName?: string | null;
    osVersion: string | null;
    agentVersion: string | null;
    tokenHash: string;
    enrollmentExpiresAt: Date;
    verifiedAt: Date;
  }): Promise<{
    device: DeviceEntity;
    credential: DeviceCredentialEntity;
    challenge: EnrollmentChallengeEntity;
  }> {
    return this.prisma.$transaction(async (tx: any) => {
      // Atomically claim and consume the challenge row conditionally
      const claimedRows = (await tx.$queryRaw`
        UPDATE "EnrollmentChallenge"
        SET "proofVerifiedAt" = ${params.verifiedAt},
            "consumedAt" = ${params.verifiedAt}
        WHERE "id" = ${params.challengeId}::uuid
          AND "consumedAt" IS NULL
          AND "expiresAt" > ${params.verifiedAt}
          AND "failedAttempts" < 5
        RETURNING *
      `) as EnrollmentChallengeEntity[];

      if (!claimedRows || claimedRows.length === 0) {
        const challenge = await tx.enrollmentChallenge.findUnique({
          where: { id: params.challengeId },
        });
        if (!challenge) {
          throw new Error('CHALLENGE_NOT_FOUND');
        }
        if (challenge.consumedAt !== null) {
          throw new Error('ENROLLMENT_TOKEN_ALREADY_USED');
        }
        if (challenge.expiresAt.getTime() <= params.verifiedAt.getTime()) {
          throw new Error('ENROLLMENT_TOKEN_EXPIRED');
        }
        if ((challenge.failedAttempts ?? 0) >= 5) {
          throw new Error('TOO_MANY_FAILED_PASSCODE_ATTEMPTS');
        }
        throw new Error('ENROLLMENT_CHALLENGE_CLAIM_FAILED');
      }

      const challenge = claimedRows[0];

      const device = await tx.device.update({
        where: { id: params.deviceId },
        data: {
          ...(params.reportedName && params.reportedName.trim().length >= 2
            ? { name: params.reportedName.trim() }
            : {}),
          osVersion: params.osVersion,
          agentVersion: params.agentVersion,
          lastSeenAt: params.verifiedAt,
        },
      });

      const credential = await tx.deviceCredential.create({
        data: {
          deviceId: params.deviceId,
          keyAlgorithm: params.keyAlgorithm,
          publicKeyPem: params.publicKeyPem,
          publicKeyFingerprint: params.publicKeyFingerprint,
          status: 'PENDING_CONFIRMATION',
          hardwareBacked: params.hardwareBacked,
          enrollmentTokenHash: params.tokenHash,
          enrollmentExpiresAt: params.enrollmentExpiresAt,
          active: false,
        },
      });

      return { device, credential, challenge };
    });
  }

  async confirmDeviceEnrollment(params: {
    deviceId: string;
    confirmedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity }> {
    return this.prisma.$transaction(async (tx: any) => {
      const pendingCred = await tx.deviceCredential.findFirst({
        where: {
          deviceId: params.deviceId,
          status: 'PENDING_CONFIRMATION',
        },
      });
      if (!pendingCred) {
        throw new Error('NO_PENDING_CREDENTIAL');
      }

      const credential = await tx.deviceCredential.update({
        where: { id: pendingCred.id },
        data: {
          status: 'ACTIVE',
          active: true,
          confirmedAt: params.confirmedAt,
        },
      });

      const device = await tx.device.update({
        where: { id: params.deviceId },
        data: {
          lifecycleState: 'TRUSTED',
          enrolledAt: params.confirmedAt,
        },
      });

      return { device, credential };
    });
  }

  async rejectDeviceEnrollment(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity | null }> {
    return this.prisma.$transaction(async (tx: any) => {
      const existing = await tx.device.findUnique({
        where: { id: params.deviceId },
      });
      if (!existing) {
        throw new Error('DEVICE_NOT_FOUND');
      }

      await tx.deviceCredential.updateMany({
        where: {
          deviceId: params.deviceId,
          status: 'PENDING_CONFIRMATION',
        },
        data: {
          status: 'REVOKED',
          active: false,
          revokedAt: params.revokedAt,
        },
      });

      const updatedDevice = await tx.device.update({
        where: { id: params.deviceId },
        data: {
          lifecycleState: 'REVOKED',
          revokedAt: params.revokedAt,
        },
      });

      const revokedCred = await tx.deviceCredential.findFirst({
        where: {
          deviceId: params.deviceId,
          status: 'REVOKED',
        },
        orderBy: { revokedAt: 'desc' },
      });

      return {
        device: updatedDevice,
        credential: revokedCred ?? null,
      };
    });
  }

  async listPendingApprovalDevices(userId: string): Promise<
    Array<{ device: DeviceEntity; credential: DeviceCredentialEntity }>
  > {
    const devices = await this.prisma.device.findMany({
      where: {
        userId,
        lifecycleState: 'ENROLLMENT_PENDING',
      },
      include: {
        credentials: {
          where: {
            status: 'PENDING_CONFIRMATION',
          },
          orderBy: { createdAt: 'desc' },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    const results: Array<{ device: DeviceEntity; credential: DeviceCredentialEntity }> = [];
    for (const d of devices) {
      const pendingCred = d.credentials[0];
      if (pendingCred) {
        const { credentials, ...rawDevice } = d;
        results.push({
          device: rawDevice as DeviceEntity,
          credential: pendingCred as DeviceCredentialEntity,
        });
      }
    }
    return results;
  }

  async rotateDeviceCredential(params: {
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    rotatedAt: Date;
  }): Promise<{ device: DeviceEntity; activeCredential: DeviceCredentialEntity }> {
    return this.prisma.$transaction(async (tx: any) => {
      await tx.deviceCredential.updateMany({
        where: {
          deviceId: params.deviceId,
          active: true,
        },
        data: {
          status: 'ROTATED',
          active: false,
          rotatedAt: params.rotatedAt,
        },
      });

      const activeCredential = await tx.deviceCredential.create({
        data: {
          deviceId: params.deviceId,
          keyAlgorithm: params.keyAlgorithm,
          publicKeyPem: params.publicKeyPem,
          publicKeyFingerprint: params.publicKeyFingerprint,
          status: 'ACTIVE',
          hardwareBacked: params.hardwareBacked,
          active: true,
          confirmedAt: params.rotatedAt,
        },
      });

      const device = await tx.device.update({
        where: { id: params.deviceId },
        data: {
          lastSeenAt: params.rotatedAt,
        },
      });

      return { device, activeCredential };
    });
  }

  async updateDeviceState(params: {
    deviceId: string;
    lifecycleState: DeviceLifecycleStateEntity;
    name?: string;
    connectivityStatus?: DeviceConnectivityStatusEntity;
    lastSeenAt?: Date;
    lastHeartbeatAt?: Date;
    osVersion?: string | null;
    agentVersion?: string | null;
    currentRiskScore?: number;
    currentRiskLevel?: RiskLevelEntity;
    revokedAt?: Date | null;
    compromisedAt?: Date | null;
  }): Promise<DeviceEntity> {
    return this.prisma.device.update({
      where: { id: params.deviceId },
      data: {
        lifecycleState: params.lifecycleState,
        ...(params.name !== undefined && params.name.trim().length >= 2
          ? { name: params.name.trim() }
          : {}),
        ...(params.connectivityStatus !== undefined
          ? { connectivityStatus: params.connectivityStatus }
          : {}),
        ...(params.lastSeenAt !== undefined ? { lastSeenAt: params.lastSeenAt } : {}),
        ...(params.lastHeartbeatAt !== undefined
          ? { lastHeartbeatAt: params.lastHeartbeatAt }
          : {}),
        ...(params.osVersion !== undefined ? { osVersion: params.osVersion } : {}),
        ...(params.agentVersion !== undefined ? { agentVersion: params.agentVersion } : {}),
        ...(params.currentRiskScore !== undefined
          ? { currentRiskScore: params.currentRiskScore }
          : {}),
        ...(params.currentRiskLevel !== undefined
          ? { currentRiskLevel: params.currentRiskLevel }
          : {}),
        ...(params.revokedAt !== undefined ? { revokedAt: params.revokedAt } : {}),
        ...(params.compromisedAt !== undefined
          ? { compromisedAt: params.compromisedAt }
          : {}),
      },
    });
  }

  async revokeDeviceAndCredentials(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<DeviceEntity> {
    return this.prisma.$transaction(async (tx: any) => {
      await tx.deviceCredential.updateMany({
        where: {
          deviceId: params.deviceId,
          status: { in: ['PENDING_CONFIRMATION', 'ACTIVE'] },
        },
        data: {
          status: 'REVOKED',
          active: false,
          revokedAt: params.revokedAt,
        },
      });

      return tx.device.update({
        where: { id: params.deviceId },
        data: {
          lifecycleState: 'REVOKED',
          connectivityStatus: 'OFFLINE',
          revokedAt: params.revokedAt,
        },
      });
    });
  }

  async consumeDeviceAuthNonce(params: {
    deviceId: string;
    nonce: string;
    expiresAt: Date;
    now?: Date;
  }): Promise<boolean> {
    const now = params.now ?? new Date();
    try {
      await this.prisma.deviceAuthNonce.deleteMany({
        where: { expiresAt: { lte: now } },
      });

      const existing = await this.prisma.deviceAuthNonce.findUnique({
        where: {
          deviceId_nonce: {
            deviceId: params.deviceId,
            nonce: params.nonce,
          },
        },
      });
      if (existing) {
        return false;
      }

      await this.prisma.deviceAuthNonce.create({
        data: {
          deviceId: params.deviceId,
          nonce: params.nonce,
          expiresAt: params.expiresAt,
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  async appendAuditEvent(params: {
    actorUserId: string | null;
    actorDeviceId?: string | null;
    eventType: string;
    metadata?: Record<string, unknown>;
    timestamp?: Date;
  }): Promise<AuditChainEntry> {
    return this.prisma.$transaction(async (tx: any) => {
      // Serialize AuditLog sequenceNumber + previousEntryHash linking across concurrent transactions
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(86257201)`;

      const latest = await tx.auditLog.findFirst({
        orderBy: { sequenceNumber: 'desc' },
      });

      const sequenceNumber = latest ? latest.sequenceNumber + 1 : 1;
      const previousEntryHash = latest ? latest.entryHash : AUDIT_GENESIS_PREVIOUS_HASH;
      const id = crypto.randomUUID();
      const timestamp = params.timestamp ?? new Date();
      const timestampIso = timestamp.toISOString();
      const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});

      const entryHash = computeAuditEntryHash({
        id,
        sequenceNumber,
        actorUserId: params.actorUserId,
        eventType: params.eventType,
        timestampIso,
        metadata: sanitizedMetadata,
        previousEntryHash,
      });

      const created = await tx.auditLog.create({
        data: {
          id,
          sequenceNumber,
          actorUserId: params.actorUserId,
          actorDeviceId: params.actorDeviceId ?? null,
          eventType: params.eventType,
          timestamp,
          metadata: sanitizedMetadata as object,
          previousEntryHash,
          entryHash,
        },
      });

      return {
        id: created.id,
        sequenceNumber: created.sequenceNumber,
        actorUserId: created.actorUserId,
        eventType: created.eventType,
        timestamp: created.timestamp.toISOString(),
        metadata: (created.metadata as Record<string, unknown>) ?? {},
        previousEntryHash: created.previousEntryHash,
        entryHash: created.entryHash,
      };
    });
  }

  async listAuditEvents(params?: {
    actorUserId?: string;
    actorDeviceId?: string;
    limit?: number;
  }): Promise<AuditChainEntry[]> {
    const whereClause: Record<string, unknown> = {};
    if (params?.actorUserId) whereClause.actorUserId = params.actorUserId;
    if (params?.actorDeviceId) whereClause.actorDeviceId = params.actorDeviceId;

    const rows = await this.prisma.auditLog.findMany({
      where: Object.keys(whereClause).length > 0 ? whereClause : undefined,
      orderBy: { sequenceNumber: 'desc' },
      take: Math.min(params?.limit ?? 50, 100),
    });

    return rows.map((r: any) => ({
      id: r.id,
      sequenceNumber: r.sequenceNumber,
      actorUserId: r.actorUserId,
      eventType: r.eventType,
      timestamp: r.timestamp.toISOString(),
      metadata: (r.metadata as Record<string, unknown>) ?? {},
      previousEntryHash: r.previousEntryHash,
      entryHash: r.entryHash,
    }));
  }

  async getAllAuditEventsOrdered(): Promise<AuditChainEntry[]> {
    const rows = await this.prisma.auditLog.findMany({
      orderBy: { sequenceNumber: 'asc' },
    });
    return rows.map((r: any) => ({
      id: r.id,
      sequenceNumber: r.sequenceNumber,
      actorUserId: r.actorUserId,
      eventType: r.eventType,
      timestamp: r.timestamp.toISOString(),
      metadata: (r.metadata as Record<string, unknown>) ?? {},
      previousEntryHash: r.previousEntryHash,
      entryHash: r.entryHash,
    }));
  }

  async createNotification(params: {
    userId: string;
    type: string;
    severity: string;
    category?: string;
    title: string;
    message: string;
    relatedDeviceId?: string | null;
    relatedDeviceName?: string | null;
    relatedEventId?: string | null;
    actionLabel?: string | null;
    actionTarget?: string | null;
    metadata?: Record<string, unknown>;
    createdAt?: Date;
  }): Promise<NotificationEntity> {
    const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});
    const created = await this.prisma.notification.create({
      data: {
        userId: params.userId,
        type: params.type,
        severity: params.severity,
        category: params.category ?? 'Security',
        title: params.title,
        message: params.message,
        createdAt: params.createdAt ?? new Date(),
        relatedDeviceId: params.relatedDeviceId ?? null,
        relatedDeviceName: params.relatedDeviceName ?? null,
        relatedEventId: params.relatedEventId ?? null,
        actionLabel: params.actionLabel ?? null,
        actionTarget: params.actionTarget ?? null,
        metadata: sanitizedMetadata as object,
      },
    });
    return {
      ...created,
      metadata: (created.metadata as Record<string, unknown>) ?? {},
    };
  }

  async listNotificationsByUserId(
    userId: string,
    options?: { includeDismissed?: boolean; limit?: number }
  ): Promise<NotificationEntity[]> {
    const rows = await this.prisma.notification.findMany({
      where: {
        userId,
        ...(options?.includeDismissed ? {} : { dismissedAt: null }),
      },
      orderBy: { createdAt: 'desc' },
      take: Math.min(options?.limit ?? 50, 100),
    });
    return rows.map((r: any) => ({
      ...r,
      metadata: (r.metadata as Record<string, unknown>) ?? {},
    }));
  }

  async markNotificationRead(params: {
    notificationId: string;
    userId: string;
    readAt?: Date;
  }): Promise<NotificationEntity | null> {
    const existing = await this.prisma.notification.findUnique({
      where: { id: params.notificationId },
    });
    if (!existing || existing.userId !== params.userId) {
      return null;
    }
    const updated = await this.prisma.notification.update({
      where: { id: params.notificationId },
      data: { readAt: existing.readAt ?? params.readAt ?? new Date() },
    });
    return {
      ...updated,
      metadata: (updated.metadata as Record<string, unknown>) ?? {},
    };
  }

  async markAllNotificationsRead(params: {
    userId: string;
    readAt?: Date;
  }): Promise<number> {
    const res = await this.prisma.notification.updateMany({
      where: { userId: params.userId, readAt: null, dismissedAt: null },
      data: { readAt: params.readAt ?? new Date() },
    });
    return res.count;
  }

  async dismissNotification(params: {
    notificationId: string;
    userId: string;
    dismissedAt?: Date;
  }): Promise<NotificationEntity | null> {
    const existing = await this.prisma.notification.findUnique({
      where: { id: params.notificationId },
    });
    if (!existing || existing.userId !== params.userId) {
      return null;
    }
    const now = params.dismissedAt ?? new Date();
    const updated = await this.prisma.notification.update({
      where: { id: params.notificationId },
      data: {
        dismissedAt: now,
        readAt: existing.readAt ?? now,
      },
    });
    return {
      ...updated,
      metadata: (updated.metadata as Record<string, unknown>) ?? {},
    };
  }

  async createRemoteCommand(params: {
    deviceId: string;
    issuerUserId: string;
    actionType: string;
    status: string;
    statusMessage: string;
    nonce?: string;
    payloadSummary?: Record<string, unknown>;
    requestedAt?: Date;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
    expiresAt?: Date | null;
  }): Promise<RemoteCommandEntity> {
    const sanitizedSummary = sanitizeLogMetadata(params.payloadSummary ?? {});
    const created = await this.prisma.remoteCommand.create({
      data: {
        deviceId: params.deviceId,
        issuerUserId: params.issuerUserId,
        actionType: params.actionType,
        status: params.status,
        statusMessage: params.statusMessage,
        nonce: params.nonce ?? crypto.randomBytes(16).toString('hex'),
        payloadSummary: sanitizedSummary as object,
        requestedAt: params.requestedAt ?? new Date(),
        deliveredAt: params.deliveredAt ?? null,
        acknowledgedAt: params.acknowledgedAt ?? null,
        completedAt: params.completedAt ?? null,
        expiresAt: params.expiresAt ?? null,
      },
    });
    return {
      ...created,
      payloadSummary: (created.payloadSummary as Record<string, unknown>) ?? {},
    };
  }

  async findRemoteCommandById(commandId: string): Promise<RemoteCommandEntity | null> {
    const row = await this.prisma.remoteCommand.findUnique({ where: { id: commandId } });
    if (!row) return null;
    return {
      ...row,
      payloadSummary: (row.payloadSummary as Record<string, unknown>) ?? {},
    };
  }

  async listRemoteCommandsByDeviceId(
    deviceId: string,
    userId: string,
    limit = 25
  ): Promise<RemoteCommandEntity[]> {
    const rows = await this.prisma.remoteCommand.findMany({
      where: { deviceId, issuerUserId: userId },
      orderBy: { requestedAt: 'desc' },
      take: Math.min(limit, 100),
    });
    return rows.map((r: any) => ({
      ...r,
      payloadSummary: (r.payloadSummary as Record<string, unknown>) ?? {},
    }));
  }

  async listPendingCommandsForDevice(deviceId: string): Promise<RemoteCommandEntity[]> {
    const rows = await this.prisma.remoteCommand.findMany({
      where: {
        deviceId,
        status: { in: ['PENDING', 'QUEUED', 'DELIVERED', 'ACKNOWLEDGED'] },
      },
      orderBy: { requestedAt: 'asc' },
    });
    return rows.map((r: any) => ({
      ...r,
      payloadSummary: (r.payloadSummary as Record<string, unknown>) ?? {},
    }));
  }

  async updateRemoteCommandState(params: {
    commandId: string;
    status: string;
    statusMessage?: string;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
  }): Promise<RemoteCommandEntity> {
    const existing = await this.prisma.remoteCommand.findUnique({
      where: { id: params.commandId },
    });
    if (!existing) {
      throw new Error('COMMAND_NOT_FOUND');
    }
    if (!isLegalCommandTransition(existing.status, params.status)) {
      throw new Error(
        `ILLEGAL_COMMAND_TRANSITION:${existing.status}->${params.status}`
      );
    }
    const updated = await this.prisma.remoteCommand.update({
      where: { id: params.commandId },
      data: {
        status: params.status,
        ...(params.statusMessage !== undefined ? { statusMessage: params.statusMessage } : {}),
        ...(params.deliveredAt !== undefined ? { deliveredAt: params.deliveredAt } : {}),
        ...(params.acknowledgedAt !== undefined ? { acknowledgedAt: params.acknowledgedAt } : {}),
        ...(params.completedAt !== undefined ? { completedAt: params.completedAt } : {}),
      },
    });
    return {
      ...updated,
      payloadSummary: (updated.payloadSummary as Record<string, unknown>) ?? {},
    };
  }

  async expireStaleRemoteCommands(params: {
    deviceId: string;
    now?: Date;
  }): Promise<RemoteCommandEntity[]> {
    const now = params.now ?? new Date();
    const candidates = await this.prisma.remoteCommand.findMany({
      where: {
        deviceId: params.deviceId,
        status: { in: ['PENDING', 'QUEUED', 'DELIVERED'] },
        expiresAt: { lte: now },
      },
    });
    const expired: RemoteCommandEntity[] = [];
    for (const cmd of candidates) {
      const u = await this.prisma.remoteCommand.update({
        where: { id: cmd.id },
        data: {
          status: 'EXPIRED',
          statusMessage: 'Command expired before device check-in.',
        },
      });
      expired.push({
        ...u,
        payloadSummary: (u.payloadSummary as Record<string, unknown>) ?? {},
      });
    }
    return expired;
  }

  async createCommandResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED' | string;
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<CommandResultEntity> {
    const sanitizedMeta = sanitizeLogMetadata(params.resultMetadata ?? {});
    const created = await this.prisma.commandResult.create({
      data: {
        commandId: params.commandId,
        deviceId: params.deviceId,
        status: params.status,
        receivedAt: params.receivedAt ?? new Date(),
        completedAt: params.completedAt ?? null,
        errorCode: params.errorCode ?? null,
        safeMessage: params.safeMessage,
        deviceTimestamp: params.deviceTimestamp ?? null,
        resultMetadata: sanitizedMeta as object,
      },
    });
    return {
      ...created,
      resultMetadata: (created.resultMetadata as Record<string, unknown>) ?? {},
    };
  }

  async recordCommandExecutionResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED';
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<{
    command: RemoteCommandEntity;
    result: CommandResultEntity;
    idempotentReplay: boolean;
  }> {
    return this.prisma.$transaction(async (tx: any) => {
      const existingCmd = await tx.remoteCommand.findUnique({
        where: { id: params.commandId },
      });
      if (!existingCmd) {
        throw new Error('COMMAND_NOT_FOUND');
      }
      if (existingCmd.deviceId !== params.deviceId) {
        throw new Error('COMMAND_DEVICE_MISMATCH');
      }

      const existingResult = await tx.commandResult.findUnique({
        where: { commandId: params.commandId },
      });
      if (existingResult) {
        // Idempotent same-status replay only; conflicting status is rejected.
        if (existingResult.status !== params.status) {
          throw new Error(
            `CONFLICTING_COMMAND_RESULT:${existingResult.status}->${params.status}`
          );
        }
        return {
          command: {
            ...existingCmd,
            payloadSummary: (existingCmd.payloadSummary as Record<string, unknown>) ?? {},
          },
          result: {
            ...existingResult,
            resultMetadata: (existingResult.resultMetadata as Record<string, unknown>) ?? {},
          },
          idempotentReplay: true,
        };
      }

      if (TERMINAL_COMMAND_STATUSES.has(existingCmd.status)) {
        throw new Error(
          `ILLEGAL_COMMAND_TRANSITION:${existingCmd.status}->${params.status}`
        );
      }
      if (!isLegalCommandTransition(existingCmd.status, params.status)) {
        throw new Error(
          `ILLEGAL_COMMAND_TRANSITION:${existingCmd.status}->${params.status}`
        );
      }

      const now = params.receivedAt ?? new Date();
      const completedAt = params.completedAt ?? now;
      const sanitizedMeta = sanitizeLogMetadata(params.resultMetadata ?? {});

      const updatedCmd = await tx.remoteCommand.update({
        where: { id: params.commandId },
        data: {
          status: params.status,
          statusMessage: params.safeMessage,
          completedAt,
        },
      });

      const createdResult = await tx.commandResult.create({
        data: {
          commandId: params.commandId,
          deviceId: params.deviceId,
          status: params.status,
          receivedAt: now,
          completedAt,
          errorCode: params.errorCode ?? null,
          safeMessage: params.safeMessage,
          deviceTimestamp: params.deviceTimestamp ?? null,
          resultMetadata: sanitizedMeta as object,
        },
      });

      return {
        command: {
          ...updatedCmd,
          payloadSummary: (updatedCmd.payloadSummary as Record<string, unknown>) ?? {},
        },
        result: {
          ...createdResult,
          resultMetadata: (createdResult.resultMetadata as Record<string, unknown>) ?? {},
        },
        idempotentReplay: false,
      };
    });
  }

  async findCommandResultByCommandId(commandId: string): Promise<CommandResultEntity | null> {
    const row = await this.prisma.commandResult.findUnique({ where: { commandId } });
    if (!row) return null;
    return {
      ...row,
      resultMetadata: (row.resultMetadata as Record<string, unknown>) ?? {},
    };
  }

  async createSecurityEvent(params: {
    userId: string;
    deviceId?: string | null;
    category: string;
    type: string;
    severity: string;
    occurredAt?: Date;
    receivedAt?: Date;
    title: string;
    description: string;
    metadata?: Record<string, unknown>;
    source?: string;
    correlationId?: string | null;
  }): Promise<SecurityEventEntity> {
    const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});
    const created = await this.prisma.securityEvent.create({
      data: {
        userId: params.userId,
        deviceId: params.deviceId ?? null,
        category: params.category,
        type: params.type,
        severity: params.severity,
        occurredAt: params.occurredAt ?? new Date(),
        receivedAt: params.receivedAt ?? new Date(),
        title: params.title,
        description: params.description,
        metadata: sanitizedMetadata as object,
        source: params.source ?? 'WEB',
        correlationId: params.correlationId ?? null,
      },
    });
    return {
      ...created,
      metadata: (created.metadata as Record<string, unknown>) ?? {},
    };
  }

  async listSecurityEventsByUserId(
    userId: string,
    options?: {
      category?: string;
      deviceId?: string;
      severity?: string;
      since?: Date;
      until?: Date;
      limit?: number;
    }
  ): Promise<SecurityEventEntity[]> {
    const where: Record<string, unknown> = { userId };
    if (options?.category) where.category = options.category;
    if (options?.deviceId) where.deviceId = options.deviceId;
    if (options?.severity) where.severity = options.severity;
    if (options?.since || options?.until) {
      where.occurredAt = {
        ...(options?.since ? { gte: options.since } : {}),
        ...(options?.until ? { lte: options.until } : {}),
      };
    }

    const rows = await this.prisma.securityEvent.findMany({
      where,
      orderBy: { occurredAt: 'desc' },
      take: Math.min(options?.limit ?? 60, 100),
    });
    return rows.map((r: any) => ({
      ...r,
      metadata: (r.metadata as Record<string, unknown>) ?? {},
    }));
  }

  async createDeviceHeartbeat(params: {
    deviceId: string;
    reportedName?: string | null;
    connectivityStatus?: 'ONLINE' | 'OFFLINE';
    batteryLevel?: number | null;
    charging?: boolean | null;
    networkType?: 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN';
    osVersion?: string | null;
    agentVersion?: string | null;
    permissionSummary?: string | null;
    securitySummary?: string | null;
    locationPermissionGranted?: boolean | null;
    receivedAt?: Date;
  }): Promise<DeviceHeartbeatEntity> {
    const receivedAt = params.receivedAt ?? new Date();
    const connectivityStatus = params.connectivityStatus ?? 'ONLINE';

    const created = await this.prisma.$transaction(async (tx: any) => {
      const hb = await tx.deviceHeartbeat.create({
        data: {
          deviceId: params.deviceId,
          connectivityStatus,
          batteryLevel: params.batteryLevel ?? null,
          charging: params.charging ?? null,
          networkType: params.networkType ?? 'UNKNOWN',
          osVersion: params.osVersion ?? null,
          agentVersion: params.agentVersion ?? null,
          permissionSummary: params.permissionSummary ?? null,
          securitySummary: params.securitySummary ?? null,
          locationPermissionGranted: params.locationPermissionGranted ?? null,
          receivedAt,
        },
      });

      const existingDevice = await tx.device.findUnique({
        where: { id: params.deviceId },
      });
      if (
        existingDevice &&
        (!existingDevice.lastHeartbeatAt ||
          receivedAt.getTime() >= existingDevice.lastHeartbeatAt.getTime())
      ) {
        const canTransitionLifecycle =
          existingDevice.lifecycleState === 'TRUSTED' ||
          existingDevice.lifecycleState === 'ACTIVE' ||
          existingDevice.lifecycleState === 'OFFLINE';
        const nextLifecycleState = canTransitionLifecycle
          ? connectivityStatus === 'OFFLINE'
            ? 'OFFLINE'
            : 'ACTIVE'
          : existingDevice.lifecycleState;

        await tx.device.update({
          where: { id: params.deviceId },
          data: {
            lifecycleState: nextLifecycleState,
            connectivityStatus,
            lastHeartbeatAt: receivedAt,
            lastSeenAt: receivedAt,
            ...(params.reportedName && params.reportedName.trim().length >= 2
              ? { name: params.reportedName.trim() }
              : {}),
            ...(params.osVersion !== undefined && params.osVersion !== null
              ? { osVersion: params.osVersion }
              : {}),
            ...(params.agentVersion !== undefined && params.agentVersion !== null
              ? { agentVersion: params.agentVersion }
              : {}),
          },
        });
      }

      return hb;
    });

    return {
      ...created,
      connectivityStatus: (created.connectivityStatus as 'ONLINE' | 'OFFLINE') ?? 'ONLINE',
      networkType:
        (created.networkType as 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN') ?? 'UNKNOWN',
    };
  }

  async getLatestDeviceHeartbeat(deviceId: string): Promise<DeviceHeartbeatEntity | null> {
    const row = await this.prisma.deviceHeartbeat.findFirst({
      where: { deviceId },
      orderBy: { receivedAt: 'desc' },
    });
    if (!row) return null;
    return {
      ...row,
      connectivityStatus: (row.connectivityStatus as 'ONLINE' | 'OFFLINE') ?? 'ONLINE',
      networkType: (row.networkType as 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN') ?? 'UNKNOWN',
    };
  }

  async listDeviceHeartbeats(
    deviceId: string,
    options?: { since?: Date; limit?: number }
  ): Promise<DeviceHeartbeatEntity[]> {
    const where: Record<string, unknown> = { deviceId };
    if (options?.since) {
      where.receivedAt = { gte: options.since };
    }
    const rows = await this.prisma.deviceHeartbeat.findMany({
      where,
      orderBy: { receivedAt: 'desc' },
      take: Math.min(options?.limit ?? 100, 200),
    });
    return rows.reverse().map((row: any) => ({
      ...row,
      connectivityStatus: (row.connectivityStatus as 'ONLINE' | 'OFFLINE') ?? 'ONLINE',
      networkType: (row.networkType as 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN') ?? 'UNKNOWN',
    }));
  }

  async saveRiskAssessment(params: {
    userId: string;
    deviceId?: string | null;
    score: number;
    status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
    factors: string[];
    recommendations: string[];
    updatedAt?: Date;
  }): Promise<RiskAssessmentEntity> {
    const created = await this.prisma.riskAssessment.create({
      data: {
        userId: params.userId,
        deviceId: params.deviceId ?? null,
        score: params.score,
        status: params.status,
        factors: params.factors as object,
        recommendations: params.recommendations as object,
        updatedAt: params.updatedAt ?? new Date(),
      },
    });
    return {
      id: created.id,
      userId: created.userId,
      deviceId: created.deviceId,
      score: created.score,
      status: created.status as RiskAssessmentEntity['status'],
      factors: Array.isArray(created.factors) ? (created.factors as string[]) : [],
      recommendations: Array.isArray(created.recommendations)
        ? (created.recommendations as string[])
        : [],
      updatedAt: created.updatedAt,
    };
  }

  async getLatestRiskAssessment(
    userId: string,
    deviceId?: string | null
  ): Promise<RiskAssessmentEntity | null> {
    const row = await this.prisma.riskAssessment.findFirst({
      where: {
        userId,
        ...(deviceId !== undefined ? { deviceId } : {}),
      },
      orderBy: { updatedAt: 'desc' },
    });
    if (!row) return null;
    return {
      id: row.id,
      userId: row.userId,
      deviceId: row.deviceId,
      score: row.score,
      status: row.status as RiskAssessmentEntity['status'],
      factors: Array.isArray(row.factors) ? (row.factors as string[]) : [],
      recommendations: Array.isArray(row.recommendations)
        ? (row.recommendations as string[])
        : [],
      updatedAt: row.updatedAt,
    };
  }

  async createThreatCheck(params: {
    userId: string;
    deviceId?: string | null;
    submittedUrl: string;
    normalizedDomain: string;
    verdict: string;
    riskScore: number;
    summary: string;
    recommendedGuidance: string;
    source?: string;
    checkedAt?: Date;
    indicators: Array<{
      code: string;
      category: string;
      severity: string;
      title: string;
      explanation: string;
      weight: number;
    }>;
  }): Promise<ThreatCheckEntity> {
    const now = params.checkedAt ?? new Date();
    const clampedScore = Math.max(0, Math.min(100, Math.round(params.riskScore)));

    const created = await this.prisma.threatCheck.create({
      data: {
        userId: params.userId,
        deviceId: params.deviceId ?? null,
        submittedUrl: params.submittedUrl,
        normalizedDomain: params.normalizedDomain,
        verdict: params.verdict,
        riskScore: clampedScore,
        summary: params.summary,
        recommendedGuidance: params.recommendedGuidance,
        source: params.source ?? 'WEB',
        checkedAt: now,
        indicators: {
          create: params.indicators.map((ind) => ({
            code: ind.code,
            category: ind.category,
            severity: ind.severity,
            title: ind.title,
            explanation: ind.explanation,
            weight: Math.max(0, Math.min(100, Math.round(ind.weight))),
            createdAt: now,
          })),
        },
      },
      include: {
        indicators: {
          orderBy: [{ weight: 'desc' }, { code: 'asc' }],
        },
      },
    });

    return {
      id: created.id,
      userId: created.userId,
      deviceId: created.deviceId,
      submittedUrl: created.submittedUrl,
      normalizedDomain: created.normalizedDomain,
      verdict: created.verdict,
      riskScore: created.riskScore,
      summary: created.summary,
      recommendedGuidance: created.recommendedGuidance,
      source: created.source,
      checkedAt: created.checkedAt,
      indicators: created.indicators.map((i: any) => ({
        id: i.id,
        threatCheckId: i.threatCheckId,
        code: i.code,
        category: i.category,
        severity: i.severity,
        title: i.title,
        explanation: i.explanation,
        weight: i.weight,
        createdAt: i.createdAt,
      })),
    };
  }

  async listThreatChecksByUserId(
    userId: string,
    options?: {
      deviceId?: string;
      verdict?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ items: ThreatCheckEntity[]; totalCount: number }> {
    const where: Record<string, unknown> = { userId };
    if (options?.deviceId) where.deviceId = options.deviceId;
    if (options?.verdict) where.verdict = options.verdict;

    const take = Math.max(1, Math.min(options?.limit ?? 25, 100));
    const skip = Math.max(0, options?.offset ?? 0);

    const [rows, totalCount] = await Promise.all([
      this.prisma.threatCheck.findMany({
        where,
        orderBy: [{ checkedAt: 'desc' }, { id: 'desc' }],
        take,
        skip,
        include: {
          indicators: {
            orderBy: [{ weight: 'desc' }, { code: 'asc' }],
          },
        },
      }),
      this.prisma.threatCheck.count({ where }),
    ]);

    return {
      totalCount,
      items: rows.map((row: any) => ({
        id: row.id,
        userId: row.userId,
        deviceId: row.deviceId,
        submittedUrl: row.submittedUrl,
        normalizedDomain: row.normalizedDomain,
        verdict: row.verdict,
        riskScore: row.riskScore,
        summary: row.summary,
        recommendedGuidance: row.recommendedGuidance,
        source: row.source,
        checkedAt: row.checkedAt,
        indicators: (row.indicators ?? []).map((i: any) => ({
          id: i.id,
          threatCheckId: i.threatCheckId,
          code: i.code,
          category: i.category,
          severity: i.severity,
          title: i.title,
          explanation: i.explanation,
          weight: i.weight,
          createdAt: i.createdAt,
        })),
      })),
    };
  }

  async listAllRemoteCommandsByUserId(
    userId: string,
    limit = 100
  ): Promise<RemoteCommandEntity[]> {
    const rows = await this.prisma.remoteCommand.findMany({
      where: { issuerUserId: userId },
      orderBy: { requestedAt: 'desc' },
      take: Math.max(1, Math.min(limit, 200)),
    });
    return rows.map((r: any) => ({
      ...r,
      payloadSummary: (r.payloadSummary as Record<string, unknown>) ?? {},
    }));
  }
}

/**
 * Deterministic in-memory IdentityRepository implementation matching all PostgreSQL/Prisma constraints.
 * Used in unit/integration tests and when a live PostgreSQL instance is not reachable in the sandbox.
 */
export class InMemoryIdentityRepository implements IdentityRepository {
  public readonly backendType = 'MEMORY_FALLBACK' as const;

  private readonly users = new Map<string, UserEntity>();
  private readonly credentials = new Map<string, UserCredentialEntity>();
  private readonly sessions = new Map<string, DeviceSessionEntity>();
  private readonly devices = new Map<string, DeviceEntity>();
  private readonly deviceCredentials = new Map<string, DeviceCredentialEntity>();
  private readonly enrollmentChallenges = new Map<string, EnrollmentChallengeEntity>();
  private readonly deviceAuthNonces = new Map<string, DeviceAuthNonceEntity>();
  private readonly auditLogs: Array<{ entry: AuditChainEntry; actorDeviceId: string | null }> = [];
  private readonly notifications = new Map<string, NotificationEntity>();
  private readonly remoteCommands = new Map<string, RemoteCommandEntity>();
  private readonly commandResults = new Map<string, CommandResultEntity>();
  private readonly securityEvents = new Map<string, SecurityEventEntity>();
  private readonly deviceHeartbeats = new Map<string, DeviceHeartbeatEntity>();
  private readonly riskAssessments = new Map<string, RiskAssessmentEntity>();
  private readonly threatChecks = new Map<string, ThreatCheckEntity>();

  async checkDatabaseHealth(_timeoutMs = 2000): Promise<{
    ok: boolean;
    backend: 'POSTGRESQL_PRISMA' | 'MEMORY_FALLBACK';
    latencyMs?: number;
    errorCode?: string;
  }> {
    return { ok: true, backend: 'MEMORY_FALLBACK', latencyMs: 0 };
  }

  async findUserByEmail(email: string): Promise<UserEntity | null> {
    const normalized = email.trim().toLowerCase();
    for (const u of this.users.values()) {
      if (u.email === normalized) {
        return { ...u };
      }
    }
    return null;
  }

  async findUserById(userId: string): Promise<UserEntity | null> {
    const u = this.users.get(userId);
    return u ? { ...u } : null;
  }

  async findCredentialByUserId(userId: string): Promise<UserCredentialEntity | null> {
    const c = this.credentials.get(userId);
    if (!c) return null;
    return {
      ...c,
      recoveryCodeHashes: c.recoveryCodeHashes.map((r) => ({ ...r })),
    };
  }

  async createUserWithCredential(params: {
    email: string;
    displayName: string;
    passwordHash: string;
  }): Promise<{ user: UserEntity; credential: UserCredentialEntity }> {
    const normalizedEmail = params.email.trim().toLowerCase();
    for (const u of this.users.values()) {
      if (u.email === normalizedEmail) {
        throw new Error('UNIQUE_CONSTRAINT_EMAIL');
      }
    }

    const now = new Date();
    const user: UserEntity = {
      id: crypto.randomUUID(),
      email: normalizedEmail,
      displayName: params.displayName.trim(),
      status: 'ACTIVE',
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const credential: UserCredentialEntity = {
      id: crypto.randomUUID(),
      userId: user.id,
      passwordHash: params.passwordHash,
      totpSecretEncrypted: null,
      totpEnabled: false,
      recoveryCodeHashes: [],
      passwordChangedAt: now,
      createdAt: now,
      updatedAt: now,
    };

    this.users.set(user.id, user);
    this.credentials.set(user.id, credential);

    return {
      user: { ...user },
      credential: { ...credential, recoveryCodeHashes: [] },
    };
  }

  async updateUserLoginState(params: {
    userId: string;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    lastLoginAt?: Date;
    status?: AccountStatus;
  }): Promise<UserEntity> {
    const existing = this.users.get(params.userId);
    if (!existing) {
      throw new Error('USER_NOT_FOUND');
    }

    const updated: UserEntity = {
      ...existing,
      failedLoginAttempts: params.failedLoginAttempts,
      lockedUntil: params.lockedUntil,
      lastLoginAt: params.lastLoginAt !== undefined ? params.lastLoginAt : existing.lastLoginAt,
      status: params.status !== undefined ? params.status : existing.status,
      updatedAt: new Date(),
    };

    this.users.set(params.userId, updated);
    return { ...updated };
  }

  async updateUserCredential(params: {
    userId: string;
    passwordHash?: string;
    totpSecretEncrypted?: string | null;
    totpEnabled?: boolean;
    recoveryCodeHashes?: StoredRecoveryCodeRecord[];
    passwordChangedAt?: Date;
  }): Promise<UserCredentialEntity> {
    const existing = this.credentials.get(params.userId);
    if (!existing) {
      throw new Error('CREDENTIAL_NOT_FOUND');
    }

    const updated: UserCredentialEntity = {
      ...existing,
      passwordHash: params.passwordHash ?? existing.passwordHash,
      totpSecretEncrypted:
        params.totpSecretEncrypted !== undefined
          ? params.totpSecretEncrypted
          : existing.totpSecretEncrypted,
      totpEnabled: params.totpEnabled ?? existing.totpEnabled,
      recoveryCodeHashes: params.recoveryCodeHashes
        ? params.recoveryCodeHashes.map((r) => ({ ...r }))
        : existing.recoveryCodeHashes,
      passwordChangedAt: params.passwordChangedAt ?? existing.passwordChangedAt,
      updatedAt: new Date(),
    };

    this.credentials.set(params.userId, updated);
    return {
      ...updated,
      recoveryCodeHashes: updated.recoveryCodeHashes.map((r) => ({ ...r })),
    };
  }

  async consumeRecoveryCodeAtomically(params: {
    userId: string;
    rawRecoveryCode: string;
    usedAtIso: string;
  }): Promise<{ valid: boolean; consumedCodeId?: string }> {
    const existing = this.credentials.get(params.userId);
    if (!existing) {
      return { valid: false };
    }

    const consumeResult = verifyAndConsumeRecoveryCode(
      params.rawRecoveryCode,
      existing.recoveryCodeHashes,
      params.usedAtIso
    );
    if (!consumeResult.valid) {
      return { valid: false };
    }

    this.credentials.set(params.userId, {
      ...existing,
      recoveryCodeHashes: consumeResult.updatedRecords.map((r) => ({ ...r })),
      updatedAt: new Date(),
    });

    return {
      valid: true,
      consumedCodeId: consumeResult.consumedCodeId,
    };
  }

  async createSession(params: {
    userId: string;
    tokenHash: string;
    csrfTokenHash: string;
    mfaVerified: boolean;
    mfaVerifiedAt: Date | null;
    stepUpVerifiedUntil: Date | null;
    stepUpActionScope?: string | null;
    ipAddressTruncated: string | null;
    userAgentSummary: string | null;
    expiresAt: Date;
    absoluteExpiresAt: Date;
  }): Promise<DeviceSessionEntity> {
    const now = new Date();
    const session: DeviceSessionEntity = {
      id: crypto.randomUUID(),
      userId: params.userId,
      deviceId: null,
      sessionType: 'WEB_CONSOLE',
      tokenHash: params.tokenHash,
      csrfTokenHash: params.csrfTokenHash,
      mfaVerified: params.mfaVerified,
      mfaVerifiedAt: params.mfaVerifiedAt,
      stepUpVerifiedUntil: params.stepUpVerifiedUntil,
      stepUpActionScope: params.stepUpActionScope ?? null,
      ipAddressTruncated: params.ipAddressTruncated,
      userAgentSummary: params.userAgentSummary,
      createdAt: now,
      lastActiveAt: now,
      expiresAt: params.expiresAt,
      absoluteExpiresAt: params.absoluteExpiresAt,
      revokedAt: null,
    };

    this.sessions.set(session.id, session);
    return { ...session };
  }

  async grantStepUp(params: {
    sessionId: string;
    stepUpVerifiedUntil: Date;
    stepUpActionScope: string;
  }): Promise<DeviceSessionEntity> {
    const existing = this.sessions.get(params.sessionId);
    if (!existing) {
      throw new Error('SESSION_NOT_FOUND');
    }
    const updated: DeviceSessionEntity = {
      ...existing,
      stepUpVerifiedUntil: params.stepUpVerifiedUntil,
      stepUpActionScope: params.stepUpActionScope,
    };
    this.sessions.set(params.sessionId, updated);
    return { ...updated };
  }

  async consumeStepUp(params: {
    sessionId: string;
    acceptableScopes: string[];
    now?: Date;
  }): Promise<boolean> {
    const existing = this.sessions.get(params.sessionId);
    if (!existing || existing.revokedAt !== null) {
      return false;
    }
    const nowMs = (params.now ?? new Date()).getTime();
    if (
      !existing.stepUpVerifiedUntil ||
      existing.stepUpVerifiedUntil.getTime() <= nowMs ||
      !existing.stepUpActionScope ||
      !params.acceptableScopes.includes(existing.stepUpActionScope)
    ) {
      return false;
    }
    this.sessions.set(params.sessionId, {
      ...existing,
      stepUpVerifiedUntil: null,
      stepUpActionScope: null,
    });
    return true;
  }

  async clearStepUp(sessionId: string): Promise<DeviceSessionEntity | null> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return null;
    const updated: DeviceSessionEntity = {
      ...existing,
      stepUpVerifiedUntil: null,
      stepUpActionScope: null,
    };
    this.sessions.set(sessionId, updated);
    return { ...updated };
  }

  async findSessionByTokenHash(tokenHash: string): Promise<DeviceSessionEntity | null> {
    for (const s of this.sessions.values()) {
      if (s.tokenHash === tokenHash) {
        return { ...s };
      }
    }
    return null;
  }

  async updateSessionActivityAndRotation(params: {
    sessionId: string;
    newTokenHash?: string;
    newCsrfTokenHash?: string;
    stepUpVerifiedUntil?: Date | null;
    stepUpActionScope?: string | null;
    lastActiveAt: Date;
    expiresAt: Date;
  }): Promise<DeviceSessionEntity> {
    const existing = this.sessions.get(params.sessionId);
    if (!existing) {
      throw new Error('SESSION_NOT_FOUND');
    }

    const updated: DeviceSessionEntity = {
      ...existing,
      tokenHash: params.newTokenHash ?? existing.tokenHash,
      csrfTokenHash: params.newCsrfTokenHash ?? existing.csrfTokenHash,
      stepUpVerifiedUntil:
        params.stepUpVerifiedUntil !== undefined
          ? params.stepUpVerifiedUntil
          : existing.stepUpVerifiedUntil,
      stepUpActionScope:
        params.stepUpActionScope !== undefined
          ? params.stepUpActionScope
          : existing.stepUpActionScope,
      lastActiveAt: params.lastActiveAt,
      expiresAt: params.expiresAt,
    };

    this.sessions.set(params.sessionId, updated);
    return { ...updated };
  }

  async revokeSessionById(sessionId: string, revokedAt: Date = new Date()): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (existing && existing.revokedAt === null) {
      this.sessions.set(sessionId, { ...existing, revokedAt });
    }
  }

  async revokeUserSessionById(params: {
    userId: string;
    sessionId: string;
    revokedAt?: Date;
  }): Promise<boolean> {
    const existing = this.sessions.get(params.sessionId);
    if (!existing || existing.userId !== params.userId || existing.revokedAt !== null) {
      return false;
    }
    this.sessions.set(params.sessionId, {
      ...existing,
      revokedAt: params.revokedAt ?? new Date(),
    });
    return true;
  }

  async listActiveUserSessions(
    userId: string,
    now: Date = new Date()
  ): Promise<DeviceSessionEntity[]> {
    const nowMs = now.getTime();
    return Array.from(this.sessions.values())
      .filter(
        (s) =>
          s.userId === userId &&
          s.revokedAt === null &&
          s.expiresAt.getTime() > nowMs &&
          s.absoluteExpiresAt.getTime() > nowMs
      )
      .sort((a, b) => b.lastActiveAt.getTime() - a.lastActiveAt.getTime())
      .map((s) => ({ ...s }));
  }

  async revokeAllUserSessions(userId: string, exceptSessionId?: string): Promise<number> {
    let count = 0;
    const now = new Date();
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId && session.revokedAt === null && id !== exceptSessionId) {
        this.sessions.set(id, { ...session, revokedAt: now });
        count++;
      }
    }
    return count;
  }

  async createEnrollmentPendingDevice(params: {
    userId: string;
    name: string;
    deviceType: DeviceTypeEntity;
    tokenHash: string;
    nonce: string;
    passcodeHash?: string | null;
    expiresAt: Date;
  }): Promise<{ device: DeviceEntity; challenge: EnrollmentChallengeEntity }> {
    const now = new Date();
    const device: DeviceEntity = {
      id: crypto.randomUUID(),
      userId: params.userId,
      name: params.name,
      deviceType: params.deviceType,
      lifecycleState: 'ENROLLMENT_PENDING',
      connectivityStatus: 'UNKNOWN',
      osVersion: null,
      agentVersion: null,
      currentRiskScore: 0,
      currentRiskLevel: 'LOW',
      lastHeartbeatAt: null,
      lastSeenAt: null,
      enrolledAt: null,
      revokedAt: null,
      compromisedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const challenge: EnrollmentChallengeEntity = {
      id: crypto.randomUUID(),
      deviceId: device.id,
      userId: params.userId,
      tokenHash: params.tokenHash,
      nonce: params.nonce,
      passcodeHash: params.passcodeHash ?? null,
      failedAttempts: 0,
      purpose: 'DEVICE_ENROLLMENT',
      issuedAt: now,
      expiresAt: params.expiresAt,
      proofVerifiedAt: null,
      consumedAt: null,
    };

    this.devices.set(device.id, device);
    this.enrollmentChallenges.set(challenge.id, challenge);

    return {
      device: { ...device },
      challenge: { ...challenge },
    };
  }

  async recordFailedEnrollmentChallengeAttempt(challengeId: string): Promise<number> {
    const challenge = this.enrollmentChallenges.get(challengeId);
    if (!challenge) return 0;
    challenge.failedAttempts = (challenge.failedAttempts ?? 0) + 1;
    return challenge.failedAttempts;
  }

  async recordFailedEnrollmentChallengeAttemptAtomic(
    challengeId: string,
    maxAttempts = 5,
    now = new Date()
  ): Promise<{
    allowed: boolean;
    failedAttempts: number;
    locked: boolean;
    reason?: 'LOCKED' | 'ALREADY_CONSUMED' | 'EXPIRED' | 'NOT_FOUND';
  }> {
    const challenge = this.enrollmentChallenges.get(challengeId);
    if (!challenge) {
      return { allowed: false, failedAttempts: maxAttempts, locked: true, reason: 'NOT_FOUND' };
    }
    if (challenge.consumedAt !== null) {
      return { allowed: false, failedAttempts: challenge.failedAttempts ?? 0, locked: false, reason: 'ALREADY_CONSUMED' };
    }
    if (challenge.expiresAt.getTime() <= now.getTime()) {
      return { allowed: false, failedAttempts: challenge.failedAttempts ?? 0, locked: false, reason: 'EXPIRED' };
    }
    const current = challenge.failedAttempts ?? 0;
    if (current >= maxAttempts) {
      return { allowed: false, failedAttempts: current, locked: true, reason: 'LOCKED' };
    }
    const updated = current + 1;
    challenge.failedAttempts = updated;
    const locked = updated >= maxAttempts;
    return {
      allowed: !locked,
      failedAttempts: updated,
      locked,
    };
  }

  async findEnrollmentChallengeByTokenHash(
    tokenHash: string
  ): Promise<EnrollmentChallengeEntity | null> {
    for (const c of this.enrollmentChallenges.values()) {
      if (c.tokenHash === tokenHash) {
        return { ...c };
      }
    }
    return null;
  }

  async findDeviceById(deviceId: string): Promise<DeviceEntity | null> {
    const d = this.devices.get(deviceId);
    return d ? { ...d } : null;
  }

  async listDevicesByUserId(
    userId: string,
    options?: { includeDecommissioned?: boolean }
  ): Promise<Array<{ device: DeviceEntity; credentials: DeviceCredentialEntity[] }>> {
    const matchingDevices = Array.from(this.devices.values())
      .filter(
        (d) =>
          d.userId === userId &&
          (options?.includeDecommissioned ? true : d.lifecycleState !== 'DECOMMISSIONED')
      )
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    return matchingDevices.map((d) => {
      const credentials = Array.from(this.deviceCredentials.values())
        .filter((c) => c.deviceId === d.id)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
        .map((c) => ({ ...c }));
      return {
        device: { ...d },
        credentials,
      };
    });
  }

  async findCredentialByFingerprint(fingerprint: string): Promise<DeviceCredentialEntity | null> {
    for (const c of this.deviceCredentials.values()) {
      if (c.publicKeyFingerprint === fingerprint) {
        return { ...c };
      }
    }
    return null;
  }

  async listCredentialsByDeviceId(deviceId: string): Promise<DeviceCredentialEntity[]> {
    return Array.from(this.deviceCredentials.values())
      .filter((c) => c.deviceId === deviceId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((c) => ({ ...c }));
  }

  async submitDevicePublicKey(params: {
    challengeId: string;
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    osVersion: string | null;
    agentVersion: string | null;
    tokenHash: string;
    enrollmentExpiresAt: Date;
    verifiedAt: Date;
  }): Promise<{
    device: DeviceEntity;
    credential: DeviceCredentialEntity;
    challenge: EnrollmentChallengeEntity;
  }> {
    const existingChallenge = this.enrollmentChallenges.get(params.challengeId);
    if (!existingChallenge) {
      throw new Error('CHALLENGE_NOT_FOUND');
    }
    if (existingChallenge.consumedAt !== null) {
      throw new Error('ENROLLMENT_TOKEN_ALREADY_USED');
    }
    if (existingChallenge.expiresAt.getTime() <= params.verifiedAt.getTime()) {
      throw new Error('ENROLLMENT_TOKEN_EXPIRED');
    }
    if ((existingChallenge.failedAttempts ?? 0) >= 5) {
      throw new Error('TOO_MANY_FAILED_PASSCODE_ATTEMPTS');
    }

    const existingDevice = this.devices.get(params.deviceId);
    if (!existingDevice) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    for (const c of this.deviceCredentials.values()) {
      if (c.publicKeyFingerprint === params.publicKeyFingerprint) {
        throw new Error('DUPLICATE_PUBLIC_KEY_FINGERPRINT');
      }
    }

    const updatedChallenge: EnrollmentChallengeEntity = {
      ...existingChallenge,
      proofVerifiedAt: params.verifiedAt,
      consumedAt: params.verifiedAt,
    };
    this.enrollmentChallenges.set(params.challengeId, updatedChallenge);

    const updatedDevice: DeviceEntity = {
      ...existingDevice,
      osVersion: params.osVersion,
      agentVersion: params.agentVersion,
      lastSeenAt: params.verifiedAt,
      updatedAt: params.verifiedAt,
    };
    this.devices.set(params.deviceId, updatedDevice);

    const credential: DeviceCredentialEntity = {
      id: crypto.randomUUID(),
      deviceId: params.deviceId,
      keyAlgorithm: params.keyAlgorithm,
      publicKeyPem: params.publicKeyPem,
      publicKeyFingerprint: params.publicKeyFingerprint,
      status: 'PENDING_CONFIRMATION',
      hardwareBacked: params.hardwareBacked,
      enrollmentTokenHash: params.tokenHash,
      enrollmentExpiresAt: params.enrollmentExpiresAt,
      active: false,
      createdAt: params.verifiedAt,
      confirmedAt: null,
      rotatedAt: null,
      revokedAt: null,
    };
    this.deviceCredentials.set(credential.id, credential);

    return {
      device: { ...updatedDevice },
      credential: { ...credential },
      challenge: { ...updatedChallenge },
    };
  }

  async confirmDeviceEnrollment(params: {
    deviceId: string;
    confirmedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity }> {
    const existingDevice = this.devices.get(params.deviceId);
    if (!existingDevice) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    let pendingCred: DeviceCredentialEntity | null = null;
    for (const c of this.deviceCredentials.values()) {
      if (c.deviceId === params.deviceId && c.status === 'PENDING_CONFIRMATION') {
        pendingCred = c;
        break;
      }
    }

    if (!pendingCred) {
      throw new Error('NO_PENDING_CREDENTIAL');
    }

    const updatedCred: DeviceCredentialEntity = {
      ...pendingCred,
      status: 'ACTIVE',
      active: true,
      confirmedAt: params.confirmedAt,
    };
    this.deviceCredentials.set(updatedCred.id, updatedCred);

    const updatedDevice: DeviceEntity = {
      ...existingDevice,
      lifecycleState: 'TRUSTED',
      enrolledAt: params.confirmedAt,
      updatedAt: params.confirmedAt,
    };
    this.devices.set(updatedDevice.id, updatedDevice);

    return {
      device: { ...updatedDevice },
      credential: { ...updatedCred },
    };
  }

  async rejectDeviceEnrollment(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<{ device: DeviceEntity; credential: DeviceCredentialEntity | null }> {
    const existing = this.devices.get(params.deviceId);
    if (!existing) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    let revokedCred: DeviceCredentialEntity | null = null;
    for (const [id, cred] of this.deviceCredentials.entries()) {
      if (cred.deviceId === params.deviceId && cred.status === 'PENDING_CONFIRMATION') {
        const updatedCred: DeviceCredentialEntity = {
          ...cred,
          status: 'REVOKED',
          active: false,
          revokedAt: params.revokedAt,
        };
        this.deviceCredentials.set(id, updatedCred);
        revokedCred = updatedCred;
      }
    }

    const updatedDevice: DeviceEntity = {
      ...existing,
      lifecycleState: 'REVOKED',
      revokedAt: params.revokedAt,
      updatedAt: params.revokedAt,
    };
    this.devices.set(params.deviceId, updatedDevice);

    return {
      device: { ...updatedDevice },
      credential: revokedCred ? { ...revokedCred } : null,
    };
  }

  async listPendingApprovalDevices(userId: string): Promise<
    Array<{ device: DeviceEntity; credential: DeviceCredentialEntity }>
  > {
    const results: Array<{ device: DeviceEntity; credential: DeviceCredentialEntity }> = [];
    for (const device of this.devices.values()) {
      if (device.userId === userId && device.lifecycleState === 'ENROLLMENT_PENDING') {
        let pendingCred: DeviceCredentialEntity | null = null;
        for (const cred of this.deviceCredentials.values()) {
          if (cred.deviceId === device.id && cred.status === 'PENDING_CONFIRMATION') {
            pendingCred = cred;
            break;
          }
        }
        if (pendingCred) {
          results.push({
            device: { ...device },
            credential: { ...pendingCred },
          });
        }
      }
    }
    return results.sort((a, b) => b.device.createdAt.getTime() - a.device.createdAt.getTime());
  }

  async rotateDeviceCredential(params: {
    deviceId: string;
    keyAlgorithm: KeyAlgorithmEntity;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    hardwareBacked: boolean;
    rotatedAt: Date;
  }): Promise<{ device: DeviceEntity; activeCredential: DeviceCredentialEntity }> {
    const existingDevice = this.devices.get(params.deviceId);
    if (!existingDevice) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    for (const c of this.deviceCredentials.values()) {
      if (c.publicKeyFingerprint === params.publicKeyFingerprint) {
        throw new Error('DUPLICATE_PUBLIC_KEY_FINGERPRINT');
      }
    }

    for (const [id, c] of this.deviceCredentials.entries()) {
      if (c.deviceId === params.deviceId && c.active) {
        this.deviceCredentials.set(id, {
          ...c,
          status: 'ROTATED',
          active: false,
          rotatedAt: params.rotatedAt,
        });
      }
    }

    const activeCredential: DeviceCredentialEntity = {
      id: crypto.randomUUID(),
      deviceId: params.deviceId,
      keyAlgorithm: params.keyAlgorithm,
      publicKeyPem: params.publicKeyPem,
      publicKeyFingerprint: params.publicKeyFingerprint,
      status: 'ACTIVE',
      hardwareBacked: params.hardwareBacked,
      enrollmentTokenHash: null,
      enrollmentExpiresAt: null,
      active: true,
      createdAt: params.rotatedAt,
      confirmedAt: params.rotatedAt,
      rotatedAt: null,
      revokedAt: null,
    };
    this.deviceCredentials.set(activeCredential.id, activeCredential);

    const updatedDevice: DeviceEntity = {
      ...existingDevice,
      lastSeenAt: params.rotatedAt,
      updatedAt: params.rotatedAt,
    };
    this.devices.set(updatedDevice.id, updatedDevice);

    return {
      device: { ...updatedDevice },
      activeCredential: { ...activeCredential },
    };
  }

  async updateDeviceState(params: {
    deviceId: string;
    lifecycleState: DeviceLifecycleStateEntity;
    name?: string;
    connectivityStatus?: DeviceConnectivityStatusEntity;
    lastSeenAt?: Date;
    lastHeartbeatAt?: Date;
    osVersion?: string | null;
    agentVersion?: string | null;
    currentRiskScore?: number;
    currentRiskLevel?: RiskLevelEntity;
    revokedAt?: Date | null;
    compromisedAt?: Date | null;
  }): Promise<DeviceEntity> {
    const existing = this.devices.get(params.deviceId);
    if (!existing) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    const updated: DeviceEntity = {
      ...existing,
      lifecycleState: params.lifecycleState,
      name:
        params.name !== undefined && params.name.trim().length >= 2
          ? params.name.trim()
          : existing.name,
      connectivityStatus:
        params.connectivityStatus !== undefined
          ? params.connectivityStatus
          : existing.connectivityStatus,
      lastSeenAt: params.lastSeenAt !== undefined ? params.lastSeenAt : existing.lastSeenAt,
      lastHeartbeatAt:
        params.lastHeartbeatAt !== undefined
          ? params.lastHeartbeatAt
          : existing.lastHeartbeatAt,
      osVersion: params.osVersion !== undefined ? params.osVersion : existing.osVersion,
      agentVersion:
        params.agentVersion !== undefined ? params.agentVersion : existing.agentVersion,
      currentRiskScore:
        params.currentRiskScore !== undefined
          ? params.currentRiskScore
          : existing.currentRiskScore,
      currentRiskLevel:
        params.currentRiskLevel !== undefined
          ? params.currentRiskLevel
          : existing.currentRiskLevel,
      revokedAt: params.revokedAt !== undefined ? params.revokedAt : existing.revokedAt,
      compromisedAt:
        params.compromisedAt !== undefined ? params.compromisedAt : existing.compromisedAt,
      updatedAt: new Date(),
    };

    this.devices.set(params.deviceId, updated);
    return { ...updated };
  }

  async revokeDeviceAndCredentials(params: {
    deviceId: string;
    revokedAt: Date;
  }): Promise<DeviceEntity> {
    const existing = this.devices.get(params.deviceId);
    if (!existing) {
      throw new Error('DEVICE_NOT_FOUND');
    }

    for (const [id, c] of this.deviceCredentials.entries()) {
      if (
        c.deviceId === params.deviceId &&
        (c.status === 'PENDING_CONFIRMATION' || c.status === 'ACTIVE')
      ) {
        this.deviceCredentials.set(id, {
          ...c,
          status: 'REVOKED',
          active: false,
          revokedAt: params.revokedAt,
        });
      }
    }

    const updated: DeviceEntity = {
      ...existing,
      lifecycleState: 'REVOKED',
      connectivityStatus: 'OFFLINE',
      revokedAt: params.revokedAt,
      updatedAt: params.revokedAt,
    };

    this.devices.set(params.deviceId, updated);
    return { ...updated };
  }

  async consumeDeviceAuthNonce(params: {
    deviceId: string;
    nonce: string;
    expiresAt: Date;
    now?: Date;
  }): Promise<boolean> {
    const now = params.now ?? new Date();
    for (const [key, entry] of this.deviceAuthNonces.entries()) {
      if (entry.expiresAt.getTime() <= now.getTime()) {
        this.deviceAuthNonces.delete(key);
      }
    }

    const compositeKey = `${params.deviceId}:${params.nonce}`;
    if (this.deviceAuthNonces.has(compositeKey)) {
      return false;
    }

    this.deviceAuthNonces.set(compositeKey, {
      id: crypto.randomUUID(),
      deviceId: params.deviceId,
      nonce: params.nonce,
      createdAt: now,
      expiresAt: params.expiresAt,
    });
    return true;
  }

  async appendAuditEvent(params: {
    actorUserId: string | null;
    actorDeviceId?: string | null;
    eventType: string;
    metadata?: Record<string, unknown>;
    timestamp?: Date;
  }): Promise<AuditChainEntry> {
    const latest =
      this.auditLogs.length > 0 ? this.auditLogs[this.auditLogs.length - 1].entry : null;
    const sequenceNumber = latest ? latest.sequenceNumber + 1 : 1;
    const previousEntryHash = latest ? latest.entryHash : AUDIT_GENESIS_PREVIOUS_HASH;
    const id = crypto.randomUUID();
    const timestampIso = (params.timestamp ?? new Date()).toISOString();
    const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});

    const entryHash = computeAuditEntryHash({
      id,
      sequenceNumber,
      actorUserId: params.actorUserId,
      eventType: params.eventType,
      timestampIso,
      metadata: sanitizedMetadata,
      previousEntryHash,
    });

    const entry: AuditChainEntry = {
      id,
      sequenceNumber,
      actorUserId: params.actorUserId,
      eventType: params.eventType,
      timestamp: timestampIso,
      metadata: sanitizedMetadata,
      previousEntryHash,
      entryHash,
    };

    this.auditLogs.push({ entry, actorDeviceId: params.actorDeviceId ?? null });
    return { ...entry, metadata: { ...entry.metadata } };
  }

  async listAuditEvents(params?: {
    actorUserId?: string;
    actorDeviceId?: string;
    limit?: number;
  }): Promise<AuditChainEntry[]> {
    const filtered = this.auditLogs.filter((item) => {
      if (params?.actorUserId && item.entry.actorUserId !== params.actorUserId) {
        return false;
      }
      if (
        params?.actorDeviceId &&
        item.actorDeviceId !== params.actorDeviceId &&
        item.entry.metadata?.deviceId !== params.actorDeviceId
      ) {
        return false;
      }
      return true;
    });

    return filtered
      .slice()
      .reverse()
      .slice(0, Math.min(params?.limit ?? 50, 100))
      .map((item) => ({ ...item.entry, metadata: { ...item.entry.metadata } }));
  }

  async getAllAuditEventsOrdered(): Promise<AuditChainEntry[]> {
    return this.auditLogs.map((item) => ({
      ...item.entry,
      metadata: { ...item.entry.metadata },
    }));
  }

  async createNotification(params: {
    userId: string;
    type: string;
    severity: string;
    category?: string;
    title: string;
    message: string;
    relatedDeviceId?: string | null;
    relatedDeviceName?: string | null;
    relatedEventId?: string | null;
    actionLabel?: string | null;
    actionTarget?: string | null;
    metadata?: Record<string, unknown>;
    createdAt?: Date;
  }): Promise<NotificationEntity> {
    const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});
    const entity: NotificationEntity = {
      id: crypto.randomUUID(),
      userId: params.userId,
      type: params.type,
      severity: params.severity,
      category: params.category ?? 'Security',
      title: params.title,
      message: params.message,
      createdAt: params.createdAt ?? new Date(),
      readAt: null,
      dismissedAt: null,
      relatedDeviceId: params.relatedDeviceId ?? null,
      relatedDeviceName: params.relatedDeviceName ?? null,
      relatedEventId: params.relatedEventId ?? null,
      actionLabel: params.actionLabel ?? null,
      actionTarget: params.actionTarget ?? null,
      metadata: sanitizedMetadata,
    };
    this.notifications.set(entity.id, entity);
    return { ...entity, metadata: { ...entity.metadata } };
  }

  async listNotificationsByUserId(
    userId: string,
    options?: { includeDismissed?: boolean; limit?: number }
  ): Promise<NotificationEntity[]> {
    return Array.from(this.notifications.values())
      .filter((n) => {
        if (n.userId !== userId) return false;
        if (!options?.includeDismissed && n.dismissedAt !== null) return false;
        return true;
      })
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, Math.min(options?.limit ?? 50, 100))
      .map((n) => ({ ...n, metadata: { ...n.metadata } }));
  }

  async markNotificationRead(params: {
    notificationId: string;
    userId: string;
    readAt?: Date;
  }): Promise<NotificationEntity | null> {
    const existing = this.notifications.get(params.notificationId);
    if (!existing || existing.userId !== params.userId) {
      return null;
    }
    const updated: NotificationEntity = {
      ...existing,
      readAt: existing.readAt ?? params.readAt ?? new Date(),
    };
    this.notifications.set(updated.id, updated);
    return { ...updated, metadata: { ...updated.metadata } };
  }

  async markAllNotificationsRead(params: {
    userId: string;
    readAt?: Date;
  }): Promise<number> {
    const now = params.readAt ?? new Date();
    let count = 0;
    for (const [id, n] of this.notifications.entries()) {
      if (n.userId === params.userId && n.readAt === null && n.dismissedAt === null) {
        this.notifications.set(id, { ...n, readAt: now });
        count++;
      }
    }
    return count;
  }

  async dismissNotification(params: {
    notificationId: string;
    userId: string;
    dismissedAt?: Date;
  }): Promise<NotificationEntity | null> {
    const existing = this.notifications.get(params.notificationId);
    if (!existing || existing.userId !== params.userId) {
      return null;
    }
    const now = params.dismissedAt ?? new Date();
    const updated: NotificationEntity = {
      ...existing,
      dismissedAt: now,
      readAt: existing.readAt ?? now,
    };
    this.notifications.set(updated.id, updated);
    return { ...updated, metadata: { ...updated.metadata } };
  }

  async createRemoteCommand(params: {
    deviceId: string;
    issuerUserId: string;
    actionType: string;
    status: string;
    statusMessage: string;
    nonce?: string;
    payloadSummary?: Record<string, unknown>;
    requestedAt?: Date;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
    expiresAt?: Date | null;
  }): Promise<RemoteCommandEntity> {
    const sanitizedSummary = sanitizeLogMetadata(params.payloadSummary ?? {});
    const entity: RemoteCommandEntity = {
      id: crypto.randomUUID(),
      deviceId: params.deviceId,
      issuerUserId: params.issuerUserId,
      actionType: params.actionType,
      status: params.status,
      statusMessage: params.statusMessage,
      nonce: params.nonce ?? crypto.randomBytes(16).toString('hex'),
      payloadSummary: sanitizedSummary,
      requestedAt: params.requestedAt ?? new Date(),
      deliveredAt: params.deliveredAt ?? null,
      acknowledgedAt: params.acknowledgedAt ?? null,
      completedAt: params.completedAt ?? null,
      expiresAt: params.expiresAt ?? null,
    };
    this.remoteCommands.set(entity.id, entity);
    return { ...entity, payloadSummary: { ...entity.payloadSummary } };
  }

  async findRemoteCommandById(commandId: string): Promise<RemoteCommandEntity | null> {
    const cmd = this.remoteCommands.get(commandId);
    return cmd ? { ...cmd, payloadSummary: { ...cmd.payloadSummary } } : null;
  }

  async listRemoteCommandsByDeviceId(
    deviceId: string,
    userId: string,
    limit = 25
  ): Promise<RemoteCommandEntity[]> {
    return Array.from(this.remoteCommands.values())
      .filter((c) => c.deviceId === deviceId && c.issuerUserId === userId)
      .sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime())
      .slice(0, Math.min(limit, 100))
      .map((c) => ({ ...c, payloadSummary: { ...c.payloadSummary } }));
  }

  async listPendingCommandsForDevice(deviceId: string): Promise<RemoteCommandEntity[]> {
    return Array.from(this.remoteCommands.values())
      .filter(
        (c) =>
          c.deviceId === deviceId &&
          (c.status === 'PENDING' ||
            c.status === 'QUEUED' ||
            c.status === 'DELIVERED' ||
            c.status === 'ACKNOWLEDGED')
      )
      .sort((a, b) => a.requestedAt.getTime() - b.requestedAt.getTime())
      .map((c) => ({ ...c, payloadSummary: { ...c.payloadSummary } }));
  }

  async updateRemoteCommandState(params: {
    commandId: string;
    status: string;
    statusMessage?: string;
    deliveredAt?: Date | null;
    acknowledgedAt?: Date | null;
    completedAt?: Date | null;
  }): Promise<RemoteCommandEntity> {
    const existing = this.remoteCommands.get(params.commandId);
    if (!existing) {
      throw new Error('COMMAND_NOT_FOUND');
    }
    if (!isLegalCommandTransition(existing.status, params.status)) {
      throw new Error(
        `ILLEGAL_COMMAND_TRANSITION:${existing.status}->${params.status}`
      );
    }
    const updated: RemoteCommandEntity = {
      ...existing,
      status: params.status,
      statusMessage:
        params.statusMessage !== undefined ? params.statusMessage : existing.statusMessage,
      deliveredAt:
        params.deliveredAt !== undefined ? params.deliveredAt : existing.deliveredAt,
      acknowledgedAt:
        params.acknowledgedAt !== undefined
          ? params.acknowledgedAt
          : existing.acknowledgedAt,
      completedAt:
        params.completedAt !== undefined ? params.completedAt : existing.completedAt,
    };
    this.remoteCommands.set(updated.id, updated);
    return { ...updated, payloadSummary: { ...updated.payloadSummary } };
  }

  async expireStaleRemoteCommands(params: {
    deviceId: string;
    now?: Date;
  }): Promise<RemoteCommandEntity[]> {
    const now = params.now ?? new Date();
    const expired: RemoteCommandEntity[] = [];
    for (const [id, cmd] of this.remoteCommands.entries()) {
      if (
        cmd.deviceId === params.deviceId &&
        (cmd.status === 'PENDING' || cmd.status === 'QUEUED' || cmd.status === 'DELIVERED') &&
        cmd.expiresAt &&
        cmd.expiresAt.getTime() <= now.getTime()
      ) {
        const updated: RemoteCommandEntity = {
          ...cmd,
          status: 'EXPIRED',
          statusMessage: 'Command expired before device check-in.',
        };
        this.remoteCommands.set(id, updated);
        expired.push({ ...updated, payloadSummary: { ...updated.payloadSummary } });
      }
    }
    return expired;
  }

  async createCommandResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED' | string;
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<CommandResultEntity> {
    for (const r of this.commandResults.values()) {
      if (r.commandId === params.commandId) {
        throw new Error('COMMAND_RESULT_ALREADY_EXISTS');
      }
    }
    const sanitizedMeta = sanitizeLogMetadata(params.resultMetadata ?? {});
    const entity: CommandResultEntity = {
      id: crypto.randomUUID(),
      commandId: params.commandId,
      deviceId: params.deviceId,
      status: params.status,
      receivedAt: params.receivedAt ?? new Date(),
      completedAt: params.completedAt ?? null,
      errorCode: params.errorCode ?? null,
      safeMessage: params.safeMessage,
      deviceTimestamp: params.deviceTimestamp ?? null,
      resultMetadata: sanitizedMeta,
    };
    this.commandResults.set(entity.id, entity);
    return { ...entity, resultMetadata: { ...(entity.resultMetadata ?? {}) } };
  }

  async findCommandResultByCommandId(commandId: string): Promise<CommandResultEntity | null> {
    for (const r of this.commandResults.values()) {
      if (r.commandId === commandId) {
        return { ...r, resultMetadata: { ...(r.resultMetadata ?? {}) } };
      }
    }
    return null;
  }

  async recordCommandExecutionResult(params: {
    commandId: string;
    deviceId: string;
    status: 'COMPLETED' | 'FAILED';
    receivedAt?: Date;
    completedAt?: Date | null;
    errorCode?: string | null;
    safeMessage: string;
    deviceTimestamp?: Date | null;
    resultMetadata?: Record<string, unknown>;
  }): Promise<{
    command: RemoteCommandEntity;
    result: CommandResultEntity;
    idempotentReplay: boolean;
  }> {
    const existingResult = await this.findCommandResultByCommandId(params.commandId);
    const existingCmd = await this.findRemoteCommandById(params.commandId);
    if (!existingCmd) {
      throw new Error('COMMAND_NOT_FOUND');
    }
    if (existingCmd.deviceId !== params.deviceId) {
      throw new Error('COMMAND_DEVICE_MISMATCH');
    }
    if (existingResult) {
      if (existingResult.status !== params.status) {
        throw new Error(
          `CONFLICTING_COMMAND_RESULT:${existingResult.status}->${params.status}`
        );
      }
      return {
        command: existingCmd,
        result: existingResult,
        idempotentReplay: true,
      };
    }
    if (TERMINAL_COMMAND_STATUSES.has(existingCmd.status)) {
      throw new Error(
        `ILLEGAL_COMMAND_TRANSITION:${existingCmd.status}->${params.status}`
      );
    }

    const now = params.receivedAt ?? new Date();
    const completedAt = params.completedAt ?? now;
    const updatedCommand = await this.updateRemoteCommandState({
      commandId: params.commandId,
      status: params.status,
      statusMessage: params.safeMessage,
      completedAt,
    });
    const savedResult = await this.createCommandResult({
      commandId: params.commandId,
      deviceId: params.deviceId,
      status: params.status,
      receivedAt: now,
      completedAt,
      errorCode: params.errorCode ?? null,
      safeMessage: params.safeMessage,
      deviceTimestamp: params.deviceTimestamp ?? null,
      resultMetadata: params.resultMetadata ?? {},
    });

    return {
      command: updatedCommand,
      result: savedResult,
      idempotentReplay: false,
    };
  }

  async createSecurityEvent(params: {
    userId: string;
    deviceId?: string | null;
    category: string;
    type: string;
    severity: string;
    occurredAt?: Date;
    receivedAt?: Date;
    title: string;
    description: string;
    metadata?: Record<string, unknown>;
    source?: string;
    correlationId?: string | null;
  }): Promise<SecurityEventEntity> {
    const sanitizedMetadata = sanitizeLogMetadata(params.metadata ?? {});
    const now = new Date();
    const entity: SecurityEventEntity = {
      id: crypto.randomUUID(),
      userId: params.userId,
      deviceId: params.deviceId ?? null,
      category: params.category,
      type: params.type,
      severity: params.severity,
      occurredAt: params.occurredAt ?? now,
      receivedAt: params.receivedAt ?? now,
      title: params.title,
      description: params.description,
      metadata: sanitizedMetadata,
      source: params.source ?? 'WEB',
      correlationId: params.correlationId ?? null,
    };
    this.securityEvents.set(entity.id, entity);
    return { ...entity, metadata: { ...entity.metadata } };
  }

  async listSecurityEventsByUserId(
    userId: string,
    options?: {
      category?: string;
      deviceId?: string;
      severity?: string;
      since?: Date;
      until?: Date;
      limit?: number;
    }
  ): Promise<SecurityEventEntity[]> {
    return Array.from(this.securityEvents.values())
      .filter((e) => {
        if (e.userId !== userId) return false;
        if (options?.category && e.category !== options.category) return false;
        if (options?.deviceId && e.deviceId !== options.deviceId) return false;
        if (options?.severity && e.severity !== options.severity) return false;
        if (options?.since && e.occurredAt.getTime() < options.since.getTime()) return false;
        if (options?.until && e.occurredAt.getTime() > options.until.getTime()) return false;
        return true;
      })
      .sort((a, b) => b.occurredAt.getTime() - a.occurredAt.getTime())
      .slice(0, Math.min(options?.limit ?? 60, 100))
      .map((e) => ({ ...e, metadata: { ...e.metadata } }));
  }

  async createDeviceHeartbeat(params: {
    deviceId: string;
    reportedName?: string | null;
    connectivityStatus?: 'ONLINE' | 'OFFLINE';
    batteryLevel?: number | null;
    charging?: boolean | null;
    networkType?: 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN';
    osVersion?: string | null;
    agentVersion?: string | null;
    permissionSummary?: string | null;
    securitySummary?: string | null;
    locationPermissionGranted?: boolean | null;
    receivedAt?: Date;
  }): Promise<DeviceHeartbeatEntity> {
    const receivedAt = params.receivedAt ?? new Date();
    const connectivityStatus = params.connectivityStatus ?? 'ONLINE';

    const entity: DeviceHeartbeatEntity = {
      id: crypto.randomUUID(),
      deviceId: params.deviceId,
      connectivityStatus,
      batteryLevel: params.batteryLevel ?? null,
      charging: params.charging ?? null,
      networkType: params.networkType ?? 'UNKNOWN',
      osVersion: params.osVersion ?? null,
      agentVersion: params.agentVersion ?? null,
      permissionSummary: params.permissionSummary ?? null,
      securitySummary: params.securitySummary ?? null,
      locationPermissionGranted: params.locationPermissionGranted ?? null,
      receivedAt,
    };
    this.deviceHeartbeats.set(entity.id, entity);

    const existingDevice = this.devices.get(params.deviceId);
    if (
      existingDevice &&
      (!existingDevice.lastHeartbeatAt ||
        receivedAt.getTime() >= existingDevice.lastHeartbeatAt.getTime())
    ) {
      const canTransitionLifecycle =
        existingDevice.lifecycleState === 'TRUSTED' ||
        existingDevice.lifecycleState === 'ACTIVE' ||
        existingDevice.lifecycleState === 'OFFLINE';
      const nextLifecycleState = canTransitionLifecycle
        ? connectivityStatus === 'OFFLINE'
          ? 'OFFLINE'
          : 'ACTIVE'
        : existingDevice.lifecycleState;

      this.devices.set(params.deviceId, {
        ...existingDevice,
        lifecycleState: nextLifecycleState,
        connectivityStatus,
        lastHeartbeatAt: receivedAt,
        lastSeenAt: receivedAt,
        name:
          params.reportedName && params.reportedName.trim().length >= 2
            ? params.reportedName.trim()
            : existingDevice.name,
        osVersion:
          params.osVersion !== undefined && params.osVersion !== null
            ? params.osVersion
            : existingDevice.osVersion,
        agentVersion:
          params.agentVersion !== undefined && params.agentVersion !== null
            ? params.agentVersion
            : existingDevice.agentVersion,
        updatedAt: receivedAt,
      });
    }

    return { ...entity };
  }

  async getLatestDeviceHeartbeat(deviceId: string): Promise<DeviceHeartbeatEntity | null> {
    const matches = Array.from(this.deviceHeartbeats.values())
      .filter((h) => h.deviceId === deviceId)
      .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime());
    return matches.length > 0 ? { ...matches[0] } : null;
  }

  async listDeviceHeartbeats(
    deviceId: string,
    options?: { since?: Date; limit?: number }
  ): Promise<DeviceHeartbeatEntity[]> {
    const sinceMs = options?.since ? options.since.getTime() : 0;
    const limit = Math.min(options?.limit ?? 100, 200);
    return Array.from(this.deviceHeartbeats.values())
      .filter((h) => h.deviceId === deviceId && h.receivedAt.getTime() >= sinceMs)
      .sort((a, b) => a.receivedAt.getTime() - b.receivedAt.getTime())
      .slice(-limit);
  }

  async saveRiskAssessment(params: {
    userId: string;
    deviceId?: string | null;
    score: number;
    status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
    factors: string[];
    recommendations: string[];
    updatedAt?: Date;
  }): Promise<RiskAssessmentEntity> {
    const entity: RiskAssessmentEntity = {
      id: crypto.randomUUID(),
      userId: params.userId,
      deviceId: params.deviceId ?? null,
      score: params.score,
      status: params.status,
      factors: [...params.factors],
      recommendations: [...params.recommendations],
      updatedAt: params.updatedAt ?? new Date(),
    };
    this.riskAssessments.set(entity.id, entity);
    return {
      ...entity,
      factors: [...entity.factors],
      recommendations: [...entity.recommendations],
    };
  }

  async getLatestRiskAssessment(
    userId: string,
    deviceId?: string | null
  ): Promise<RiskAssessmentEntity | null> {
    const matches = Array.from(this.riskAssessments.values())
      .filter((r) => {
        if (r.userId !== userId) return false;
        if (deviceId !== undefined && r.deviceId !== deviceId) return false;
        return true;
      })
      .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
    if (matches.length === 0) return null;
    const latest = matches[0];
    return {
      ...latest,
      factors: [...latest.factors],
      recommendations: [...latest.recommendations],
    };
  }

  async createThreatCheck(params: {
    userId: string;
    deviceId?: string | null;
    submittedUrl: string;
    normalizedDomain: string;
    verdict: string;
    riskScore: number;
    summary: string;
    recommendedGuidance: string;
    source?: string;
    checkedAt?: Date;
    indicators: Array<{
      code: string;
      category: string;
      severity: string;
      title: string;
      explanation: string;
      weight: number;
    }>;
  }): Promise<ThreatCheckEntity> {
    const now = params.checkedAt ?? new Date();
    const threatCheckId = crypto.randomUUID();
    const clampedScore = Math.max(0, Math.min(100, Math.round(params.riskScore)));

    const indicators: ThreatIndicatorEntity[] = params.indicators
      .map((ind) => ({
        id: crypto.randomUUID(),
        threatCheckId,
        code: ind.code,
        category: ind.category,
        severity: ind.severity,
        title: ind.title,
        explanation: ind.explanation,
        weight: Math.max(0, Math.min(100, Math.round(ind.weight))),
        createdAt: now,
      }))
      .sort((a, b) => (b.weight !== a.weight ? b.weight - a.weight : a.code.localeCompare(b.code)));

    const entity: ThreatCheckEntity = {
      id: threatCheckId,
      userId: params.userId,
      deviceId: params.deviceId ?? null,
      submittedUrl: params.submittedUrl,
      normalizedDomain: params.normalizedDomain,
      verdict: params.verdict,
      riskScore: clampedScore,
      summary: params.summary,
      recommendedGuidance: params.recommendedGuidance,
      source: params.source ?? 'WEB',
      checkedAt: now,
      indicators,
    };

    this.threatChecks.set(entity.id, entity);
    return {
      ...entity,
      indicators: entity.indicators.map((i) => ({ ...i })),
    };
  }

  async listThreatChecksByUserId(
    userId: string,
    options?: {
      deviceId?: string;
      verdict?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ items: ThreatCheckEntity[]; totalCount: number }> {
    const matching = Array.from(this.threatChecks.values())
      .filter((tc) => {
        if (tc.userId !== userId) return false;
        if (options?.deviceId && tc.deviceId !== options.deviceId) return false;
        if (options?.verdict && tc.verdict !== options.verdict) return false;
        return true;
      })
      .sort((a, b) => {
        const diff = b.checkedAt.getTime() - a.checkedAt.getTime();
        return diff !== 0 ? diff : b.id.localeCompare(a.id);
      });

    const totalCount = matching.length;
    const take = Math.max(1, Math.min(options?.limit ?? 25, 100));
    const skip = Math.max(0, options?.offset ?? 0);

    const paged = matching.slice(skip, skip + take).map((tc) => ({
      ...tc,
      indicators: tc.indicators.map((i) => ({ ...i })),
    }));

    return { items: paged, totalCount };
  }

  async listAllRemoteCommandsByUserId(
    userId: string,
    limit = 100
  ): Promise<RemoteCommandEntity[]> {
    const take = Math.max(1, Math.min(limit, 200));
    return Array.from(this.remoteCommands.values())
      .filter((c) => c.issuerUserId === userId)
      .sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime())
      .slice(0, take)
      .map((c) => ({ ...c, payloadSummary: { ...c.payloadSummary } }));
  }
}
