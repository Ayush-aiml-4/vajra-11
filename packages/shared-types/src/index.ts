/**
 * @vajra/shared-types
 * Core conceptual types and interfaces for the VAJRA Personal Security Platform.
 * Foundation Stage (Prompt 0001) — Simple, strongly typed, and extensible.
 */

export enum DeviceType {
  WINDOWS = 'WINDOWS',
  ANDROID = 'ANDROID',
  UNKNOWN = 'UNKNOWN',
}

export enum DeviceStatus {
  ONLINE = 'ONLINE',
  OFFLINE = 'OFFLINE',
  UNKNOWN = 'UNKNOWN',
}

export enum DeviceLifecycleState {
  UNREGISTERED = 'UNREGISTERED',
  ENROLLMENT_PENDING = 'ENROLLMENT_PENDING',
  TRUSTED = 'TRUSTED',
  ACTIVE = 'ACTIVE',
  OFFLINE = 'OFFLINE',
  LOST = 'LOST',
  COMPROMISED = 'COMPROMISED',
  REVOKED = 'REVOKED',
  DECOMMISSIONED = 'DECOMMISSIONED',
}

export enum KeyAlgorithm {
  ED25519 = 'ED25519',
  ECDSA_P256 = 'ECDSA_P256',
}

export enum DeviceCredentialStatus {
  PENDING_CONFIRMATION = 'PENDING_CONFIRMATION',
  ACTIVE = 'ACTIVE',
  ROTATED = 'ROTATED',
  REVOKED = 'REVOKED',
}

export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum CommandStatus {
  PENDING = 'PENDING',
  QUEUED = 'QUEUED',
  AUTHORIZED = 'AUTHORIZED',
  DISPATCHED = 'DISPATCHED',
  DELIVERED = 'DELIVERED',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  CANCELLED = 'CANCELLED',
  REJECTED = 'REJECTED',
}

export enum ImplementationStage {
  IMPLEMENTED = 'IMPLEMENTED',
  MOCKED = 'MOCKED',
  PLANNED = 'PLANNED',
}

export interface User {
  id: string;
  email: string;
  displayName: string;
  mfaEnabled: boolean;
  passkeyRegistered: boolean;
  createdAt: string;
  lastAuthenticatedAt?: string;
}

export interface Device {
  id: string;
  userId: string;
  name: string;
  type: DeviceType;
  status: DeviceStatus;
  osVersion: string;
  agentVersion: string;
  lastHeartbeatAt: string;
  publicKeyFingerprint: string;
  tamperStatus: 'VERIFIED' | 'TAMPER_DETECTED' | 'UNVERIFIED';
  riskScore: number; // 0 to 100 where higher security posture is reflected in console score
  riskLevel: RiskLevel;
  locationPermitted: boolean;
  isMockData?: boolean;
}

export interface SecurityEvent {
  id: string;
  deviceId: string;
  deviceName: string;
  eventType:
    | 'HEARTBEAT_CHECK'
    | 'AUTH_SUCCESS'
    | 'AUTH_FAILURE'
    | 'DEFENDER_STATUS_CHANGE'
    | 'AGENT_INTEGRITY_VERIFIED'
    | 'PERMISSION_AUDIT'
    | 'NETWORK_POSTURE_CHECK';
  summary: string;
  riskLevel: RiskLevel;
  timestamp: string;
  verifiedSignature: boolean;
  isMockData?: boolean;
}

export interface Alert {
  id: string;
  deviceId: string;
  title: string;
  description: string;
  riskLevel: RiskLevel;
  acknowledged: boolean;
  createdAt: string;
  resolvedAt?: string;
  isMockData?: boolean;
}

export interface Command {
  id: string;
  deviceId: string;
  issuerUserId: string;
  commandType: 'RING_DEVICE' | 'LOST_MODE_MESSAGE' | 'REQUEST_HEARTBEAT' | 'VERIFY_INTEGRITY';
  status: CommandStatus;
  requiresStepUpAuth: boolean;
  cryptographicNonce: string;
  issuedAt: string;
  expiresAt: string;
  completedAt?: string;
}

export interface HealthResponse {
  status: 'ok';
  service: 'vajra-api';
}

// ============================================================================
// Prompt 0007 — Notification, Security Activity & Unified Device Control Types
// ============================================================================

export type NotificationSeverity =
  | 'INFO'
  | 'ATTENTION'
  | 'WARNING'
  | 'HIGH'
  | 'CRITICAL'
  | 'PROTECTED';

export type NotificationType =
  | 'SECURITY_SIGN_IN'
  | 'SIGN_IN_FAILURE'
  | 'DEVICE_CONNECTED'
  | 'DEVICE_DISCONNECTED'
  | 'DEVICE_ONLINE'
  | 'DEVICE_OFFLINE'
  | 'NEW_NETWORK'
  | 'SECURITY_CHECK'
  | 'THREAT_DETECTED'
  | 'THREATCHECK_COMPLETED'
  | 'LOCATION_REQUESTED'
  | 'LOCATION_UPDATED'
  | 'RECOVERY_ACTION'
  | 'DEVICE_RING_REQUESTED'
  | 'RECOVERY_MESSAGE_SENT'
  | 'LOST_MODE_ENABLED'
  | 'LOST_MODE_DISABLED'
  | 'TWO_STEP_RECOMMENDED'
  | 'DEVICE_SECURITY_CHANGE'
  | 'DEVICE_COMPROMISED';

export type NotificationCategory =
  | 'Needs Attention'
  | 'Security'
  | 'Devices'
  | 'Account';

export interface NotificationItemDto {
  id: string;
  userId: string;
  type: NotificationType;
  severity: NotificationSeverity;
  category: NotificationCategory;
  title: string;
  message: string;
  createdAt: string;
  readAt: string | null;
  dismissedAt: string | null;
  relatedDeviceId: string | null;
  relatedDeviceName: string | null;
  relatedEventId: string | null;
  actionLabel: string | null;
  actionTarget: string | null;
  metadata: Record<string, unknown>;
  isDemoData?: boolean;
}

export type SecurityActivityCategory =
  | 'Authentication'
  | 'Device'
  | 'Security'
  | 'ThreatCheck'
  | 'Recovery';

export interface SecurityActivityItemDto {
  id: string;
  userId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  category: SecurityActivityCategory;
  severity: NotificationSeverity;
  title: string;
  subtitle: string;
  description: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  isDemoData?: boolean;
}

export const ALLOWLISTED_DEVICE_ACTIONS = [
  'REQUEST_LOCATION',
  'RING_DEVICE',
  'DISPLAY_RECOVERY_MESSAGE',
  'ENABLE_LOST_MODE',
  'DISABLE_LOST_MODE',
  'REQUEST_DEVICE_STATUS',
] as const;

export type AllowlistedDeviceActionType = (typeof ALLOWLISTED_DEVICE_ACTIONS)[number];

export interface DeviceLocationSummaryDto {
  accuracyMode: 'PERMISSION_AVAILABLE' | 'APPROXIMATE_NETWORK' | 'UNAVAILABLE';
  label: string;
  regionSummary: string;
  sourceLabel: string;
  updatedAt: string | null;
}

export interface RecoveryMessagePayload {
  title: string;
  message: string;
  contactInstruction?: string;
}

export interface DeviceActionRecordDto {
  id: string;
  deviceId: string;
  deviceName: string;
  issuerUserId: string;
  actionType: AllowlistedDeviceActionType;
  status: CommandStatus;
  statusMessage: string;
  payloadSummary: Record<string, unknown>;
  requestedAt: string;
  deliveredAt?: string | null;
  acknowledgedAt?: string | null;
  completedAt: string | null;
  expiresAt?: string | null;
  nonce?: string;
  locationSnapshot?: DeviceLocationSummaryDto;
  result?: CommandResultDto | null;
}

// ============================================================================
// Prompt 0008 — Security Event Engine, Risk Assessment, Command Lifecycle & Heartbeat Types
// ============================================================================

export const SECURITY_EVENT_CATEGORIES = [
  'Authentication',
  'Device',
  'Security',
  'ThreatCheck',
  'Recovery',
  'Command',
  'Network',
  'Account',
] as const;

export type SecurityEventCategory = (typeof SECURITY_EVENT_CATEGORIES)[number];

export const SECURITY_EVENT_TYPES = [
  // Authentication & Account
  'SIGN_IN_SUCCESS',
  'SIGN_IN_FAILURE',
  'SIGN_OUT',
  'MFA_ENABLED',
  'MFA_DISABLED',
  'RECOVERY_CODES_GENERATED',
  'PASSWORD_CHANGED',
  'SESSION_REVOKED',
  'ACCOUNT_LOCKED',
  // Device Lifecycle & Health
  'DEVICE_REGISTERED',
  'DEVICE_CONNECTED',
  'DEVICE_APPROVED',
  'DEVICE_DISCONNECTED',
  'DEVICE_ONLINE',
  'DEVICE_OFFLINE',
  'DEVICE_HEARTBEAT_RECEIVED',
  'DEVICE_HEARTBEAT_MISSED',
  'DEVICE_SECURITY_CHECK',
  'DEVICE_COMPROMISED',
  'DEVICE_REVOKED',
  'PERMISSION_CHANGED',
  'SECURITY_POSTURE_CHANGED',
  'SUSPICIOUS_ACTIVITY_DETECTED',
  'AGENT_STARTED',
  'AGENT_STOPPED',
  'WINDOWS_EVENT_LOG',
  // Network
  'NEW_NETWORK',
  'NETWORK_CHANGED',
  // ThreatCheck
  'THREAT_CHECK_LOW_RISK',
  'THREAT_CHECK_SUSPICIOUS',
  'THREAT_CHECK_HIGH_RISK',
  'THREATCHECK_LOW',
  'THREATCHECK_SUSPICIOUS',
  'THREATCHECK_HIGH_RISK',
  // Recovery & Commands
  'LOCATION_REQUESTED',
  'LOCATION_UPDATED',
  'RING_REQUESTED',
  'RING_ACKNOWLEDGED',
  'RECOVERY_MESSAGE_REQUESTED',
  'RECOVERY_MESSAGE_UPDATED',
  'RECOVERY_MESSAGE_DISPLAYED',
  'LOST_MODE_ENABLED',
  'LOST_MODE_DISABLED',
  'COMMAND_CREATED',
  'COMMAND_DELIVERED',
  'COMMAND_ACKNOWLEDGED',
  'COMMAND_COMPLETED',
  'COMMAND_FAILED',
  'COMMAND_EXPIRED',
  'COMMAND_CANCELLED',
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];

export const SECURITY_EVENT_SEVERITIES = [
  'INFO',
  'PROTECTED',
  'ATTENTION',
  'WARNING',
  'HIGH',
  'CRITICAL',
] as const;

export type SecurityEventSeverity = (typeof SECURITY_EVENT_SEVERITIES)[number];

export const SECURITY_EVENT_SOURCES = [
  'WEB_CONSOLE',
  'WEB',
  'AUTHENTICATION',
  'DEVICE_AGENT',
  'DEVICE',
  'WINDOWS_AGENT',
  'ANDROID_AGENT',
  'THREATCHECK',
  'RECOVERY',
  'SYSTEM',
] as const;

export type SecurityEventSource = (typeof SECURITY_EVENT_SOURCES)[number];

export interface SecurityEventDto {
  id: string;
  userId: string;
  deviceId: string | null;
  deviceName?: string | null;
  category: SecurityEventCategory;
  type: SecurityEventType;
  severity: SecurityEventSeverity;
  occurredAt: string;
  receivedAt: string;
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  source: SecurityEventSource;
  correlationId: string | null;
  isDemoData?: boolean;
}

export interface CommandResultDto {
  id: string;
  commandId: string;
  deviceId: string;
  status: 'COMPLETED' | 'FAILED';
  receivedAt: string;
  completedAt: string | null;
  errorCode: string | null;
  safeMessage: string;
  deviceTimestamp: string | null;
  resultMetadata?: Record<string, unknown>;
}

export interface DeviceHeartbeatDto {
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
  receivedAt: string;
}

export interface RiskFactorDto {
  ruleId: string;
  impact: number;
  label: string;
  detail: string;
}

export interface RiskAssessmentDto {
  id?: string;
  userId?: string;
  deviceId?: string | null;
  score: number; // 0 to 100
  status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  factors: string[];
  factorDetails: RiskFactorDto[];
  recommendations: string[];
  recommendedAction: string;
  updatedAt: string;
}

export interface SecurityAssessmentDto {
  score: number;
  status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  reasons: RiskFactorDto[];
  factors: string[];
  recommendations: string[];
  recommendedAction: string;
  calculatedAt: string;
}

export const DEMO_EVENT_SCENARIOS = [
  'NEW_SIGN_IN',
  'NEW_SIGN_IN_ALERT',
  'DEVICE_CHECK_IN',
  'SUSPICIOUS_LINK',
  'SUSPICIOUS_LINK_DETECTED',
  'LOST_MODE_TEST',
  'LOST_MODE_SIMULATION',
  'RECOVERY_MESSAGE',
  'RECOVERY_MESSAGE_TEST',
] as const;

export type DemoEventScenario = (typeof DEMO_EVENT_SCENARIOS)[number];

// ============================================================================
// ThreatCheck Persistence, Security Analytics & Report Export DTOs
// ============================================================================

export type ThreatCheckClassificationDto =
  | 'restricted destination'
  | 'suspicious indicators'
  | 'no obvious lexical indicators';

export interface ThreatIndicatorDto {
  id: string;
  code: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  title: string;
  explanation: string;
  weight: number;
  createdAt: string;
}

export interface ThreatCheckRecordDto {
  id: string;
  userId: string;
  deviceId: string | null;
  submittedUrlRedacted: string;
  normalizedDomain: string;
  verdict: 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK';
  classification?: ThreatCheckClassificationDto;
  riskScore: number;
  restrictedDestination?: boolean;
  summary: string;
  recommendedGuidance: string;
  limitationsStatement?: string;
  source: string;
  checkedAt: string;
  indicators: ThreatIndicatorDto[];
}

export interface ThreatCheckHistoryPaginationDto {
  limit: number;
  offset: number;
  totalCount: number;
  hasMore: boolean;
}

export interface AnalyticsSummaryDto {
  generatedAt: string;
  /** Always PERSISTED for live account data; SAMPLE only when explicitly demo-labeled. */
  dataSource: 'PERSISTED' | 'SAMPLE';
  /** Human-readable description of the aggregation window. */
  windowDescription: string;
  accountPosture: {
    currentScore: number;
    status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK';
    averageDeviceRiskScore: number;
  };
  devices: {
    totalCount: number;
    hardwareBackedCount: number;
    byLifecycleState: Record<string, number>;
    byPlatform: Record<string, number>;
  };
  securityEvents: {
    totalRecentCount: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
  alerts: {
    totalCount: number;
    openUnreadCount: number;
    highSeverityUnreadCount: number;
    dismissedCount: number;
  };
  threatChecks: {
    totalCount: number;
    averageRiskScore: number;
    byVerdict: Record<string, number>;
  };
  remoteCommands: {
    totalRecentCount: number;
    byStatus: Record<string, number>;
    byActionType: Record<string, number>;
  };
}

// ============================================================================
// Prompt 0048 — Active Session Inventory & Audit Chain Verification DTOs
// ============================================================================

export interface ActiveSessionDto {
  id: string;
  sessionType: 'WEB_CONSOLE' | 'DEVICE_STREAM';
  isCurrent: boolean;
  mfaVerified: boolean;
  mfaVerifiedAt: string | null;
  ipAddressTruncated: string | null;
  userAgentSummary: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  absoluteExpiresAt: string;
}

export interface AuditVerificationResultDto {
  valid: boolean;
  checkedCount: number;
  brokenAtSequence?: number;
  reason?: string;
  verifiedAt: string;
  userEventCount: number;
}



