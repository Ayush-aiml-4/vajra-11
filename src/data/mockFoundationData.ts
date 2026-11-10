/**
 * Mock / Demo Data for VAJRA Prompt 0001 Foundation Dashboard.
 * Explicitly marked as MOCKED so it is never confused with live device telemetry.
 */

import {
  Device,
  DeviceStatus,
  DeviceType,
  ImplementationStage,
  RiskLevel,
  SecurityEvent,
} from '../../packages/shared-types/src/index.ts';

export const MOCK_DEVICES: readonly Device[] = Object.freeze([
  {
    id: 'mock-dev-win-01',
    userId: 'mock-user-01',
    name: 'ASUS TUF F16',
    type: DeviceType.WINDOWS,
    status: DeviceStatus.ONLINE,
    osVersion: 'Windows 11 Pro (24H2)',
    agentVersion: '0.1.0-mock',
    lastHeartbeatAt: '2026-10-06T17:45:00Z',
    publicKeyFingerprint: 'SHA256:8F:4B:2C:9A:E1:77:04:D3 (Mock Key)',
    tamperStatus: 'VERIFIED',
    riskScore: 98,
    riskLevel: RiskLevel.LOW,
    locationPermitted: false,
    isMockData: true,
  },
  {
    id: 'mock-dev-and-02',
    userId: 'mock-user-01',
    name: 'Android Phone',
    type: DeviceType.ANDROID,
    status: DeviceStatus.ONLINE,
    osVersion: 'Android 15 (Keystore Hardware-Backed)',
    agentVersion: '0.1.0-mock',
    lastHeartbeatAt: '2026-10-06T17:46:12Z',
    publicKeyFingerprint: 'SHA256:3C:91:AA:08:5E:19:F2:6B (Mock Key)',
    tamperStatus: 'VERIFIED',
    riskScore: 98,
    riskLevel: RiskLevel.LOW,
    locationPermitted: true,
    isMockData: true,
  },
]);

export const MOCK_SECURITY_EVENTS: readonly SecurityEvent[] = Object.freeze([
  {
    id: 'mock-evt-101',
    deviceId: 'mock-dev-win-01',
    deviceName: 'ASUS TUF F16',
    eventType: 'HEARTBEAT_CHECK',
    summary: 'Simulated signed heartbeat and Windows Defender active posture verification.',
    riskLevel: RiskLevel.LOW,
    timestamp: '2026-10-06 17:45:00 UTC',
    verifiedSignature: true,
    isMockData: true,
  },
  {
    id: 'mock-evt-102',
    deviceId: 'mock-dev-and-02',
    deviceName: 'Android Phone',
    eventType: 'AGENT_INTEGRITY_VERIFIED',
    summary: 'Simulated Android Keystore attestation and Play Protect status check.',
    riskLevel: RiskLevel.LOW,
    timestamp: '2026-10-06 17:46:12 UTC',
    verifiedSignature: true,
    isMockData: true,
  },
  {
    id: 'mock-evt-103',
    deviceId: 'mock-dev-win-01',
    deviceName: 'ASUS TUF F16',
    eventType: 'PERMISSION_AUDIT',
    summary: 'Simulated least-privilege audit: zero prohibited surveillance capabilities active.',
    riskLevel: RiskLevel.LOW,
    timestamp: '2026-10-06 17:30:00 UTC',
    verifiedSignature: true,
    isMockData: true,
  },
]);

export interface ArchitectureModuleStatus {
  id: string;
  moduleName: string;
  targetStack: string;
  stage: ImplementationStage;
  description: string;
  docPath: string;
}

export const FOUNDATION_MODULES: readonly ArchitectureModuleStatus[] = Object.freeze([
  {
    id: 'mod-web-shell',
    moduleName: 'Web Console Skeleton & Navigation Shell',
    targetStack: 'React 19 · TypeScript · Tailwind CSS',
    stage: ImplementationStage.IMPLEMENTED,
    description: 'Dark cybersecurity interface with Vajra diamond motif and 6 navigation views.',
    docPath: 'apps/web/README.md',
  },
  {
    id: 'mod-health-api',
    moduleName: 'Foundation Health API (GET /api/health)',
    targetStack: 'Node.js · Express · TypeScript',
    stage: ImplementationStage.IMPLEMENTED,
    description: 'Safe liveness endpoint returning {"status":"ok","service":"vajra-api"} with zero secret exposure.',
    docPath: 'docs/api/README.md',
  },
  {
    id: 'mod-shared-types',
    moduleName: 'Shared Type System & Security Charter',
    targetStack: '@vajra/shared-types · @vajra/security · @vajra/config',
    stage: ImplementationStage.IMPLEMENTED,
    description: 'Strict TypeScript contracts, prohibited capability enforcement, and log redaction.',
    docPath: 'packages/shared-types/src/index.ts',
  },
  {
    id: 'mod-dashboard-telemetry',
    moduleName: 'Initial Dashboard Summary & Device Cards',
    targetStack: 'Mock Data Preview (ASUS TUF F16 & Android Phone)',
    stage: ImplementationStage.MOCKED,
    description: 'Static demonstration telemetry showing Protected Devices (2), Online (2), Alerts (0), Score (98/100).',
    docPath: 'src/data/mockFoundationData.ts',
  },
  {
    id: 'mod-database',
    moduleName: 'PostgreSQL + Prisma Identity & Auth Foundation',
    targetStack: 'PostgreSQL · Prisma ORM · Argon2id · AES-256-GCM TOTP · AuditLog',
    stage: ImplementationStage.IMPLEMENTED,
    description: 'User, UserCredential, PasskeyCredential, Device, DeviceCredential, DeviceSession, and hash-chained AuditLog.',
    docPath: 'prisma/schema.prisma',
  },
  {
    id: 'mod-device-identity',
    moduleName: 'Cryptographic Device Identity & Secure Enrollment (Plane 2)',
    targetStack: 'Ed25519 · ECDSA P-256 · EnrollmentChallenge · DeviceAuthNonce',
    stage: ImplementationStage.IMPLEMENTED,
    description: 'Single-use 10m enrollment tokens, Proof-of-Possession signature verification, owner confirmation, Plane 2 request signing, key rotation, and irreversible revocation.',
    docPath: 'docs/security/device-enrollment.md',
  },
  {
    id: 'mod-windows-agent',
    moduleName: 'Windows Security Agent',
    targetStack: 'C# · .NET 8+ · Windows TPM / CNG',
    stage: ImplementationStage.PLANNED,
    description: 'Legitimate Windows service collecting permitted security posture telemetry with hardware-bound keys.',
    docPath: 'apps/windows-agent/README.md',
  },
  {
    id: 'mod-android-app',
    moduleName: 'Android Security Application',
    targetStack: 'Kotlin · Native Android · Android Keystore',
    stage: ImplementationStage.PLANNED,
    description: 'Permission-aware Android app supporting signed heartbeats, remote phone ringing, and recovery screen.',
    docPath: 'apps/android/README.md',
  },
]);
