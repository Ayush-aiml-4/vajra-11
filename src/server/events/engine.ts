import crypto from 'node:crypto';
import {
  DemoEventScenario,
  RiskAssessmentDto,
  SECURITY_EVENT_CATEGORIES,
  SECURITY_EVENT_SEVERITIES,
  SECURITY_EVENT_SOURCES,
  SECURITY_EVENT_TYPES,
  SecurityEventCategory,
  SecurityEventDto,
  SecurityEventSeverity,
  SecurityEventSource,
  SecurityEventType,
} from '../../../packages/shared-types/src/index.ts';
import {
  sanitizeLogMetadata,
} from '../../../packages/security/src/node.ts';
import {
  IdentityRepository,
  NotificationEntity,
  RiskAssessmentEntity,
  SecurityEventEntity,
} from '../db/repository.ts';

/**
 * Clock-skew validation constants (Prompt 0008 Part 6):
 * - Maximum future clock skew: 5 minutes (300,000 ms).
 *   Events claiming to occur more than 5 minutes in the future are rejected.
 * - Maximum past age: 30 days (2,592,000,000 ms).
 *   Events older than 30 days are rejected to prevent stale event replay.
 */
export const MAX_FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const MAX_PAST_EVENT_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_METADATA_BYTES = 8 * 1024; // 8 KB max serialized metadata

const FORBIDDEN_METADATA_KEY_PATTERNS = [
  /password/i,
  /passcode/i,
  /secret/i,
  /token/i,
  /private[_-]?key/i,
  /recovery[_-]?codes?$/i,
  /cookie/i,
  /authorization/i,
  /bearer/i,
  /credential/i,
  /totp/i,
  /raw[_-]?hash/i,
];

const FORBIDDEN_VALUE_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /^Bearer\s+[A-Za-z0-9\-._~+/]+=*$/i,
  /^\$argon2id\$/i,
];

export interface IngestSecurityEventInput {
  userId: string;
  deviceId?: string | null;
  category?: SecurityEventCategory | string;
  type: SecurityEventType | string;
  severity?: SecurityEventSeverity | string;
  occurredAt?: Date | string;
  title?: string;
  description?: string;
  metadata?: Record<string, unknown>;
  source?: SecurityEventSource | string;
  correlationId?: string | null;
  skipNotificationPolicy?: boolean;
  skipAuditRecord?: boolean;
}

export interface IngestSecurityEventResult {
  event: SecurityEventDto;
  notificationCreated: NotificationEntity | null;
  riskAssessment: RiskAssessmentDto;
}

/**
 * Validates that event metadata contains no forbidden keys or secret values,
 * and sanitizes any nested fields using sanitizeLogMetadata().
 */
export function validateAndSanitizeEventMetadata(
  rawMetadata: unknown
): { valid: true; sanitized: Record<string, unknown> } | { valid: false; error: string } {
  if (rawMetadata === undefined || rawMetadata === null) {
    return { valid: true, sanitized: {} };
  }

  if (typeof rawMetadata !== 'object' || Array.isArray(rawMetadata)) {
    return { valid: false, error: 'Event metadata must be a JSON object.' };
  }

  let serialized: string;
  try {
    serialized = JSON.stringify(rawMetadata);
  } catch {
    return { valid: false, error: 'Event metadata could not be serialized.' };
  }

  if (Buffer.byteLength(serialized, 'utf8') > MAX_METADATA_BYTES) {
    return {
      valid: false,
      error: `Event metadata exceeds the maximum allowed size of ${MAX_METADATA_BYTES} bytes.`,
    };
  }

  const checkObjectRecursive = (obj: Record<string, unknown>, depth = 0): string | null => {
    if (depth > 5) {
      return 'Event metadata nesting depth exceeds maximum allowed limit (5).';
    }
    for (const [key, value] of Object.entries(obj)) {
      for (const pattern of FORBIDDEN_METADATA_KEY_PATTERNS) {
        if (pattern.test(key)) {
          return `Event metadata contains forbidden sensitive field "${key}".`;
        }
      }
      if (typeof value === 'string') {
        for (const valPattern of FORBIDDEN_VALUE_PATTERNS) {
          if (valPattern.test(value.trim())) {
            return `Event metadata field "${key}" contains forbidden secret or key material.`;
          }
        }
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        const nestedErr = checkObjectRecursive(value as Record<string, unknown>, depth + 1);
        if (nestedErr) return nestedErr;
      }
    }
    return null;
  };

  const forbiddenError = checkObjectRecursive(rawMetadata as Record<string, unknown>);
  if (forbiddenError) {
    return { valid: false, error: forbiddenError };
  }

  const sanitized = sanitizeLogMetadata(rawMetadata as Record<string, unknown>);
  return { valid: true, sanitized };
}

/**
 * Maps internal semantic event types to calm, consumer-friendly default titles, descriptions,
 * categories, and severities so raw enum identifiers never leak into user-facing copy.
 */
export function resolveDefaultEventCopy(
  type: SecurityEventType,
  deviceName?: string | null
): {
  category: SecurityEventCategory;
  severity: SecurityEventSeverity;
  title: string;
  description: string;
} {
  const targetLabel = deviceName || 'your device';

  switch (type) {
    case 'SIGN_IN_SUCCESS':
      return {
        category: 'Authentication',
        severity: 'INFO',
        title: 'Account sign-in verified',
        description: 'A verified session was opened for your VAJRA account.',
      };
    case 'SIGN_IN_FAILURE':
      return {
        category: 'Authentication',
        severity: 'WARNING',
        title: 'Unrecognized sign-in attempt blocked',
        description: 'An unsuccessful sign-in attempt was recorded and blocked.',
      };
    case 'MFA_ENABLED':
      return {
        category: 'Authentication',
        severity: 'PROTECTED',
        title: 'Two-step verification enabled',
        description: 'Your account is now protected with two-step verification and recovery codes.',
      };
    case 'MFA_DISABLED':
      return {
        category: 'Authentication',
        severity: 'ATTENTION',
        title: 'Two-step verification turned off',
        description: 'Two-step verification was removed from your account.',
      };
    case 'RECOVERY_CODES_GENERATED':
      return {
        category: 'Account',
        severity: 'INFO',
        title: 'Recovery codes updated',
        description: 'A fresh set of single-use account recovery codes was generated.',
      };
    case 'PASSWORD_CHANGED':
      return {
        category: 'Account',
        severity: 'PROTECTED',
        title: 'Account password updated',
        description: 'Your account password was changed and active sessions were refreshed.',
      };
    case 'SESSION_REVOKED':
    case 'SIGN_OUT':
      return {
        category: 'Authentication',
        severity: 'INFO',
        title: 'Session signed out',
        description: 'An active session was signed out from your account.',
      };
    case 'ACCOUNT_LOCKED':
      return {
        category: 'Authentication',
        severity: 'HIGH',
        title: 'Account temporarily protected after repeated sign-in failures',
        description: 'Sign-in was temporarily paused after multiple unsuccessful attempts.',
      };
    case 'DEVICE_REGISTERED':
    case 'DEVICE_CONNECTED':
      return {
        category: 'Device',
        severity: 'INFO',
        title: `Device connected: ${targetLabel}`,
        description: `${targetLabel} completed identity registration and is awaiting approval or active connection.`,
      };
    case 'DEVICE_APPROVED':
      return {
        category: 'Device',
        severity: 'PROTECTED',
        title: `Device approved and trusted: ${targetLabel}`,
        description: `${targetLabel} is now a verified trusted device on your account.`,
      };
    case 'DEVICE_DISCONNECTED':
    case 'DEVICE_OFFLINE':
      return {
        category: 'Device',
        severity: 'ATTENTION',
        title: `${targetLabel} went offline`,
        description: `${targetLabel} has not checked in recently. Queued protection actions will run when it reconnects.`,
      };
    case 'DEVICE_ONLINE':
    case 'DEVICE_HEARTBEAT_RECEIVED':
      return {
        category: 'Device',
        severity: 'PROTECTED',
        title: `Security check completed on ${targetLabel}`,
        description: `${targetLabel} checked in and confirmed its protection status.`,
      };
    case 'DEVICE_HEARTBEAT_MISSED':
      return {
        category: 'Device',
        severity: 'WARNING',
        title: `Missed check-in from ${targetLabel}`,
        description: `${targetLabel} missed its scheduled status check-in.`,
      };
    case 'DEVICE_SECURITY_CHECK':
      return {
        category: 'Security',
        severity: 'PROTECTED',
        title: `Security check verified on ${targetLabel}`,
        description: `${targetLabel} passed its automated security posture check.`,
      };
    case 'DEVICE_COMPROMISED':
    case 'SUSPICIOUS_ACTIVITY_DETECTED':
      return {
        category: 'Security',
        severity: 'CRITICAL',
        title: `Unusual security activity on ${targetLabel}`,
        description: `${targetLabel} reported a critical security change that requires your immediate review.`,
      };
    case 'DEVICE_REVOKED':
      return {
        category: 'Device',
        severity: 'WARNING',
        title: `Device access removed: ${targetLabel}`,
        description: `${targetLabel} was removed from your trusted devices and its credentials were revoked.`,
      };
    case 'PERMISSION_CHANGED':
      return {
        category: 'Device',
        severity: 'ATTENTION',
        title: `Permissions updated on ${targetLabel}`,
        description: `Device permission settings were updated on ${targetLabel}.`,
      };
    case 'SECURITY_POSTURE_CHANGED':
      return {
        category: 'Security',
        severity: 'ATTENTION',
        title: `Protection status updated on ${targetLabel}`,
        description: `The security posture for ${targetLabel} changed and was re-evaluated.`,
      };
    case 'AGENT_STARTED':
      return {
        category: 'Device',
        severity: 'INFO',
        title: `Protection agent started on ${targetLabel}`,
        description: `The VAJRA protection agent started and verified its local status on ${targetLabel}.`,
      };
    case 'AGENT_STOPPED':
      return {
        category: 'Device',
        severity: 'ATTENTION',
        title: `Protection agent stopped on ${targetLabel}`,
        description: `The VAJRA protection agent stopped running on ${targetLabel}.`,
      };
    case 'WINDOWS_EVENT_LOG':
      return {
        category: 'Device',
        severity: 'INFO',
        title: `System event recorded on ${targetLabel}`,
        description: `A Windows system or application log entry was reported from ${targetLabel}.`,
      };
    case 'NEW_NETWORK':
    case 'NETWORK_CHANGED':
      return {
        category: 'Network',
        severity: 'INFO',
        title: `Network connection updated on ${targetLabel}`,
        description: `${targetLabel} connected to a different network environment.`,
      };
    case 'THREAT_CHECK_LOW_RISK':
    case 'THREATCHECK_LOW':
      return {
        category: 'ThreatCheck',
        severity: 'PROTECTED',
        title: 'ThreatCheck inspection: Low risk',
        description: 'No known phishing or deceptive patterns were detected in the inspected item.',
      };
    case 'THREAT_CHECK_SUSPICIOUS':
    case 'THREATCHECK_SUSPICIOUS':
      return {
        category: 'ThreatCheck',
        severity: 'WARNING',
        title: 'ThreatCheck flagged a suspicious item',
        description: 'Unusual address patterns or urgency cues were found. Proceed with caution.',
      };
    case 'THREAT_CHECK_HIGH_RISK':
    case 'THREATCHECK_HIGH_RISK':
      return {
        category: 'ThreatCheck',
        severity: 'HIGH',
        title: 'High-risk link or message detected',
        description: 'ThreatCheck identified strong indicators of credential phishing or impersonation.',
      };
    case 'LOCATION_REQUESTED':
      return {
        category: 'Recovery',
        severity: 'INFO',
        title: `Location check requested for ${targetLabel}`,
        description: `A location update was requested for ${targetLabel}.`,
      };
    case 'LOCATION_UPDATED':
      return {
        category: 'Recovery',
        severity: 'PROTECTED',
        title: `Location updated for ${targetLabel}`,
        description: `${targetLabel} reported its latest location summary.`,
      };
    case 'RING_REQUESTED':
      return {
        category: 'Recovery',
        severity: 'INFO',
        title: `Sound alert requested on ${targetLabel}`,
        description: `A high-volume locator chime was requested for ${targetLabel}.`,
      };
    case 'RING_ACKNOWLEDGED':
      return {
        category: 'Recovery',
        severity: 'PROTECTED',
        title: `Sound alert played on ${targetLabel}`,
        description: `${targetLabel} acknowledged and played the recovery sound alert.`,
      };
    case 'RECOVERY_MESSAGE_REQUESTED':
    case 'RECOVERY_MESSAGE_UPDATED':
      return {
        category: 'Recovery',
        severity: 'INFO',
        title: `Recovery message prepared for ${targetLabel}`,
        description: `A lock-screen return message was configured for ${targetLabel}.`,
      };
    case 'RECOVERY_MESSAGE_DISPLAYED':
      return {
        category: 'Recovery',
        severity: 'PROTECTED',
        title: `Recovery message displayed on ${targetLabel}`,
        description: `${targetLabel} confirmed the recovery message is active on its screen.`,
      };
    case 'LOST_MODE_ENABLED':
      return {
        category: 'Recovery',
        severity: 'HIGH',
        title: `Lost Mode recorded for ${targetLabel}`,
        description: `${targetLabel} is marked as lost in your VAJRA account (server-side status; physical screen lock and live GPS are not performed by the agent).`,
      };
    case 'LOST_MODE_DISABLED':
      return {
        category: 'Recovery',
        severity: 'PROTECTED',
        title: `Lost Mode turned off on ${targetLabel}`,
        description: `${targetLabel} returned to normal protected operation.`,
      };
    case 'COMMAND_CREATED':
      return {
        category: 'Command',
        severity: 'INFO',
        title: `Protection command queued for ${targetLabel}`,
        description: `An authorized protection command was created for ${targetLabel}.`,
      };
    case 'COMMAND_DELIVERED':
      return {
        category: 'Command',
        severity: 'INFO',
        title: `Protection command delivered to ${targetLabel}`,
        description: `${targetLabel} received the pending protection command.`,
      };
    case 'COMMAND_ACKNOWLEDGED':
      return {
        category: 'Command',
        severity: 'INFO',
        title: `Protection command acknowledged by ${targetLabel}`,
        description: `${targetLabel} verified and started executing the protection command.`,
      };
    case 'COMMAND_COMPLETED':
      return {
        category: 'Command',
        severity: 'PROTECTED',
        title: `Protection action completed on ${targetLabel}`,
        description: `${targetLabel} finished running the requested protection action.`,
      };
    case 'COMMAND_FAILED':
      return {
        category: 'Command',
        severity: 'WARNING',
        title: `Protection action could not complete on ${targetLabel}`,
        description: `${targetLabel} reported that the requested action could not be completed.`,
      };
    case 'COMMAND_EXPIRED':
      return {
        category: 'Command',
        severity: 'ATTENTION',
        title: `Queued action expired for ${targetLabel}`,
        description: `A pending command for ${targetLabel} expired before the device came online.`,
      };
    case 'COMMAND_CANCELLED':
      return {
        category: 'Command',
        severity: 'INFO',
        title: `Queued action cancelled for ${targetLabel}`,
        description: `You cancelled a pending protection command for ${targetLabel}.`,
      };
    default:
      return {
        category: 'Security',
        severity: 'INFO',
        title: 'Security activity recorded',
        description: 'A verified security event was recorded on your account.',
      };
  }
}

export class SecurityEventEngine {
  private readonly repository: IdentityRepository;

  constructor(repository: IdentityRepository) {
    this.repository = repository;
  }

  /**
   * Validates, persists, evaluates notification policy, updates deterministic risk score,
   * and records an audit chain entry for a security event.
   */
  async ingestEvent(input: IngestSecurityEventInput): Promise<IngestSecurityEventResult> {
    if (!input.userId || typeof input.userId !== 'string') {
      throw new Error('INVALID_EVENT_USER: Authenticated userId is required.');
    }

    const user = await this.repository.findUserById(input.userId);
    if (!user) {
      throw new Error('INVALID_EVENT_USER: User not found.');
    }

    // Validate event type
    if (!SECURITY_EVENT_TYPES.includes(input.type as SecurityEventType)) {
      throw new Error(`UNSUPPORTED_EVENT_TYPE: "${String(input.type)}" is not a valid SecurityEventType.`);
    }
    const eventType = input.type as SecurityEventType;

    // Validate device ownership if deviceId is provided
    let deviceName: string | null = null;
    if (input.deviceId) {
      const device = await this.repository.findDeviceById(input.deviceId);
      if (!device || device.userId !== input.userId) {
        throw new Error('CROSS_USER_DEVICE_REFERENCE: Device does not belong to the authenticated user.');
      }
      deviceName = device.name;
    }

    const defaults = resolveDefaultEventCopy(eventType, deviceName);

    // Validate category
    const category = (input.category || defaults.category) as SecurityEventCategory;
    if (!SECURITY_EVENT_CATEGORIES.includes(category)) {
      throw new Error(`UNSUPPORTED_EVENT_CATEGORY: "${String(category)}" is not a valid SecurityEventCategory.`);
    }

    // Validate severity
    const severity = (input.severity || defaults.severity) as SecurityEventSeverity;
    if (!SECURITY_EVENT_SEVERITIES.includes(severity)) {
      throw new Error(`UNSUPPORTED_EVENT_SEVERITY: "${String(severity)}" is not a valid SecurityEventSeverity.`);
    }

    // Validate source
    const source = (input.source || 'WEB') as SecurityEventSource;
    if (!SECURITY_EVENT_SOURCES.includes(source)) {
      throw new Error(`UNSUPPORTED_EVENT_SOURCE: "${String(source)}" is not a valid SecurityEventSource.`);
    }

    // Validate timestamp and clock skew (Prompt 0008 Part 6)
    const receivedAt = new Date();
    let occurredAt = receivedAt;
    if (input.occurredAt !== undefined && input.occurredAt !== null) {
      const parsed = input.occurredAt instanceof Date ? input.occurredAt : new Date(input.occurredAt);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error('INVALID_EVENT_TIMESTAMP: occurredAt is not a valid timestamp.');
      }
      const skewMs = parsed.getTime() - receivedAt.getTime();
      if (skewMs > MAX_FUTURE_CLOCK_SKEW_MS) {
        throw new Error(
          `CLOCK_SKEW_EXCEEDED: Event timestamp cannot be more than ${MAX_FUTURE_CLOCK_SKEW_MS / 60000} minutes in the future.`
        );
      }
      if (receivedAt.getTime() - parsed.getTime() > MAX_PAST_EVENT_AGE_MS) {
        throw new Error('STALE_EVENT_TIMESTAMP: Event timestamp is older than 30 days.');
      }
      occurredAt = parsed;
    }

    // Validate and sanitize metadata (Prompt 0008 Part 7)
    const metaValidation = validateAndSanitizeEventMetadata(input.metadata);
    if (!metaValidation.valid) {
      throw new Error(`INVALID_EVENT_METADATA: ${metaValidation.error}`);
    }

    const title = (input.title?.trim() || defaults.title).slice(0, 180);
    const description = (input.description?.trim() || defaults.description).slice(0, 600);

    const createdEvent = await this.repository.createSecurityEvent({
      userId: input.userId,
      deviceId: input.deviceId ?? null,
      category,
      type: eventType,
      severity,
      occurredAt,
      receivedAt,
      title,
      description,
      metadata: metaValidation.sanitized,
      source,
      correlationId: input.correlationId ?? null,
    });

    // Evaluate Notification Policy (Prompt 0008 Part 8)
    let notificationCreated: NotificationEntity | null = null;
    if (!input.skipNotificationPolicy) {
      notificationCreated = await this.evaluateNotificationPolicy(createdEvent, deviceName);
    }

    // Evaluate Deterministic Risk Engine (Prompt 0008 Part 9)
    const riskAssessment = await this.evaluateUserRisk(input.userId, input.deviceId ?? null);

    // Append tamper-evident audit entry for high-consequence events
    if (!input.skipAuditRecord && this.shouldAuditEvent(eventType, severity)) {
      await this.appendAuditEntry(createdEvent);
    }

    return {
      event: this.toDto(createdEvent, deviceName),
      notificationCreated,
      riskAssessment,
    };
  }

  /**
   * Notification Policy Engine (Prompt 0008 Part 8):
   * Automatically creates user-facing notifications for actionable or high-consequence events,
   * while suppressing duplicate notifications for identical event + device within a 5-minute window.
   */
  private async evaluateNotificationPolicy(
    event: SecurityEventEntity,
    deviceName: string | null
  ): Promise<NotificationEntity | null> {
    const policyMap: Partial<
      Record<
        SecurityEventType,
        {
          notificationType: string;
          severity: string;
          category: string;
          actionLabel: string | null;
          actionTarget: string | null;
        }
      >
    > = {
      MFA_DISABLED: {
        notificationType: 'MFA_DISABLED',
        severity: 'WARNING',
        category: 'Account',
        actionLabel: 'Review Settings',
        actionTarget: 'settings',
      },
      ACCOUNT_LOCKED: {
        notificationType: 'SUSPICIOUS_ACTIVITY',
        severity: 'CRITICAL',
        category: 'Authentication',
        actionLabel: 'Review Activity',
        actionTarget: 'activity',
      },
      DEVICE_APPROVED: {
        notificationType: 'NEW_DEVICE_CONNECTED',
        severity: 'PROTECTED',
        category: 'Devices',
        actionLabel: 'View Devices',
        actionTarget: 'devices',
      },
      DEVICE_OFFLINE: {
        notificationType: 'DEVICE_OFFLINE',
        severity: 'ATTENTION',
        category: 'Devices',
        actionLabel: 'Inspect Device',
        actionTarget: 'devices',
      },
      DEVICE_HEARTBEAT_MISSED: {
        notificationType: 'DEVICE_OFFLINE',
        severity: 'WARNING',
        category: 'Devices',
        actionLabel: 'Inspect Device',
        actionTarget: 'devices',
      },
      DEVICE_COMPROMISED: {
        notificationType: 'SUSPICIOUS_ACTIVITY',
        severity: 'CRITICAL',
        category: 'Security',
        actionLabel: 'Inspect Device',
        actionTarget: 'devices',
      },
      SUSPICIOUS_ACTIVITY_DETECTED: {
        notificationType: 'SUSPICIOUS_ACTIVITY',
        severity: 'HIGH',
        category: 'Security',
        actionLabel: 'Review Activity',
        actionTarget: 'activity',
      },
      DEVICE_REVOKED: {
        notificationType: 'DEVICE_REVOKED',
        severity: 'WARNING',
        category: 'Devices',
        actionLabel: 'View Devices',
        actionTarget: 'devices',
      },
      THREAT_CHECK_HIGH_RISK: {
        notificationType: 'HIGH_RISK_THREAT_CHECK',
        severity: 'HIGH',
        category: 'ThreatCheck',
        actionLabel: 'Open ThreatCheck',
        actionTarget: 'threat-check',
      },
      THREATCHECK_HIGH_RISK: {
        notificationType: 'HIGH_RISK_THREAT_CHECK',
        severity: 'HIGH',
        category: 'ThreatCheck',
        actionLabel: 'Open ThreatCheck',
        actionTarget: 'threat-check',
      },
      THREAT_CHECK_SUSPICIOUS: {
        notificationType: 'HIGH_RISK_THREAT_CHECK',
        severity: 'WARNING',
        category: 'ThreatCheck',
        actionLabel: 'Open ThreatCheck',
        actionTarget: 'threat-check',
      },
      THREATCHECK_SUSPICIOUS: {
        notificationType: 'HIGH_RISK_THREAT_CHECK',
        severity: 'WARNING',
        category: 'ThreatCheck',
        actionLabel: 'Open ThreatCheck',
        actionTarget: 'threat-check',
      },
      LOST_MODE_ENABLED: {
        notificationType: 'LOST_MODE_CHANGED',
        severity: 'HIGH',
        category: 'Recovery',
        actionLabel: 'Manage Recovery',
        actionTarget: 'devices',
      },
      LOST_MODE_DISABLED: {
        notificationType: 'LOST_MODE_CHANGED',
        severity: 'PROTECTED',
        category: 'Recovery',
        actionLabel: 'View Device',
        actionTarget: 'devices',
      },
      RECOVERY_MESSAGE_DISPLAYED: {
        notificationType: 'RECOVERY_ACTION_COMPLETED',
        severity: 'INFO',
        category: 'Recovery',
        actionLabel: 'View Device',
        actionTarget: 'devices',
      },
      COMMAND_FAILED: {
        notificationType: 'RECOVERY_ACTION_COMPLETED',
        severity: 'WARNING',
        category: 'Devices',
        actionLabel: 'View Device',
        actionTarget: 'devices',
      },
      COMMAND_EXPIRED: {
        notificationType: 'DEVICE_OFFLINE',
        severity: 'ATTENTION',
        category: 'Devices',
        actionLabel: 'View Device',
        actionTarget: 'devices',
      },
    };

    const rule = policyMap[event.type as SecurityEventType];
    if (!rule) {
      // Also notify on any explicit HIGH or CRITICAL severity event not in the map
      if (event.severity !== 'HIGH' && event.severity !== 'CRITICAL') {
        return null;
      }
    }

    // Deduplication check: avoid spamming identical notification titles within 5 minutes
    const existingNotifications = await this.repository.listNotificationsByUserId(event.userId, {
      includeDismissed: false,
    });
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    const duplicate = existingNotifications.find(
      (n) =>
        n.title === event.title &&
        n.relatedDeviceId === event.deviceId &&
        n.createdAt.getTime() >= fiveMinutesAgo &&
        n.readAt === null
    );
    if (duplicate) {
      return duplicate;
    }

    return this.repository.createNotification({
      userId: event.userId,
      type: rule?.notificationType ?? 'SECURITY_ADVISORY',
      severity: rule?.severity ?? event.severity,
      category: rule?.category ?? event.category,
      title: event.title,
      message: event.description,
      relatedDeviceId: event.deviceId,
      relatedDeviceName: deviceName,
      relatedEventId: event.id,
      actionLabel: rule?.actionLabel ?? 'Review Activity',
      actionTarget: rule?.actionTarget ?? 'activity',
      metadata: {
        sourceEventType: event.type,
        source: event.source,
      },
    });
  }

  /**
   * Deterministic Risk Evaluation Engine (Prompt 0008 Part 9):
   * Computes a transparent 0–100 protection score and status ('PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK')
   * from real account state: MFA posture, device health/heartbeats, Lost Mode, recent ThreatCheck alerts,
   * and recent failed sign-in attempts.
   */
  async evaluateUserRisk(userId: string, targetDeviceId: string | null = null): Promise<RiskAssessmentDto> {
    let score = 100;
    const factors: string[] = [];
    const recommendations: string[] = [];

    const credential = await this.repository.findCredentialByUserId(userId);
    const devicesWithCreds = await this.repository.listDevicesByUserId(userId);
    const recentEvents = await this.repository.listSecurityEventsByUserId(userId, { limit: 60 });
    const recentCommandsLists = await Promise.all(
      devicesWithCreds.map((d) =>
        this.repository.listRemoteCommandsByDeviceId(d.device.id, userId, 15)
      )
    );
    const recentCommands = recentCommandsLists.flat();

    // 1. Two-step verification (MFA) posture
    if (!credential?.totpEnabled) {
      score -= 18;
      factors.push('Two-step verification is not enabled on your account');
      recommendations.push('Turn on two-step verification in Settings to protect sign-ins and recovery actions.');
    } else {
      factors.push('Two-step verification is active');
    }

    // 2. Device fleet posture
    const activeDevices = devicesWithCreds.map((d) => d.device);
    if (activeDevices.length === 0) {
      score -= 10;
      factors.push('No trusted devices are currently enrolled');
      recommendations.push('Register your primary computer or phone to enable continuous protection.');
    } else {
      const compromisedDevices = activeDevices.filter((d) => d.lifecycleState === 'COMPROMISED');
      const suspendedDevices = activeDevices.filter((d) => d.lifecycleState === 'LOST');
      const pendingDevices = activeDevices.filter((d) => d.lifecycleState === 'ENROLLMENT_PENDING');

      if (compromisedDevices.length > 0) {
        score -= 40;
        factors.push(
          `${compromisedDevices.length} device${compromisedDevices.length > 1 ? 's' : ''} flagged with critical security risk`
        );
        recommendations.push(
          `Inspect ${compromisedDevices[0].name} immediately or remove its access if unrecognized.`
        );
      }

      if (suspendedDevices.length > 0) {
        score -= 22;
        factors.push(
          `${suspendedDevices.length} device${suspendedDevices.length > 1 ? 's' : ''} currently in Lost Mode (${suspendedDevices.map((d) => d.name).join(', ')})`
        );
        recommendations.push('Review device check-in activity or clear Lost Mode once recovered, or revoke device access if unrecoverable.');
      }

      if (pendingDevices.length > 0) {
        score -= 8;
        factors.push(
          `${pendingDevices.length} device${pendingDevices.length > 1 ? 's' : ''} awaiting enrollment approval`
        );
        recommendations.push('Approve or remove pending device registrations in Devices.');
      }

      // Check stale heartbeats (> 24 hours without check-in on TRUSTED/ACTIVE devices)
      const staleThreshold = Date.now() - 24 * 60 * 60 * 1000;
      const staleDevices = activeDevices.filter(
        (d) =>
          (d.lifecycleState === 'TRUSTED' || d.lifecycleState === 'ACTIVE') &&
          (!d.lastHeartbeatAt || d.lastHeartbeatAt.getTime() < staleThreshold)
      );
      if (staleDevices.length > 0) {
        score -= Math.min(16, staleDevices.length * 8);
        factors.push(
          `${staleDevices.length} trusted device${staleDevices.length > 1 ? 's have' : ' has'} not checked in within 24 hours`
        );
        recommendations.push(`Verify connectivity on ${staleDevices[0].name} and run a status check.`);
      }
    }

    // 3. Recent high-risk ThreatCheck detections (within last 24 hours)
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const recentHighRiskThreats = recentEvents.filter(
      (e) =>
        (e.type === 'THREAT_CHECK_HIGH_RISK' || e.type === 'THREATCHECK_HIGH_RISK') &&
        e.occurredAt.getTime() >= oneDayAgo
    );
    if (recentHighRiskThreats.length > 0) {
      score -= 15;
      factors.push(
        `${recentHighRiskThreats.length} high-risk link or message inspection${recentHighRiskThreats.length > 1 ? 's' : ''} in the last 24 hours`
      );
      recommendations.push('Avoid interacting with flagged links and review recent ThreatCheck guidance.');
    }

    // 4. Recent failed sign-ins (within last 6 hours)
    const sixHoursAgo = Date.now() - 6 * 60 * 60 * 1000;
    const recentFailedLogins = recentEvents.filter(
      (e) => e.type === 'SIGN_IN_FAILURE' && e.occurredAt.getTime() >= sixHoursAgo
    );
    if (recentFailedLogins.length >= 2) {
      score -= 12;
      factors.push(`${recentFailedLogins.length} blocked sign-in attempts in the past 6 hours`);
      recommendations.push('Review recent sign-in activity and ensure your password remains unique.');
    }

    // 5. Failed or expired recovery commands (within last 24 hours)
    const recentFailedCommands = recentCommands.filter(
      (c) => (c.status === 'FAILED' || c.status === 'EXPIRED') && c.requestedAt.getTime() >= oneDayAgo
    );
    if (recentFailedCommands.length > 0) {
      score -= 6;
      factors.push(`${recentFailedCommands.length} protection command could not reach a device recently`);
    }

    const clampedScore = Math.max(0, Math.min(100, score));
    let status: 'PROTECTED' | 'ATTENTION NEEDED' | 'HIGH RISK' = 'PROTECTED';
    if (clampedScore < 60) {
      status = 'HIGH RISK';
    } else if (clampedScore < 85) {
      status = 'ATTENTION NEEDED';
    }

    if (factors.length === 0) {
      factors.push('All registered devices and account protections are verified');
    }
    if (recommendations.length === 0) {
      recommendations.push('Your personal security posture is strong. No immediate actions are needed.');
    }

    const saved: RiskAssessmentEntity = await this.repository.saveRiskAssessment({
      userId,
      deviceId: targetDeviceId,
      score: clampedScore,
      status,
      factors,
      recommendations,
    });

    const riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' =
      clampedScore < 40
        ? 'CRITICAL'
        : clampedScore < 60
        ? 'HIGH'
        : clampedScore < 85
        ? 'MODERATE'
        : 'LOW';

    return {
      id: saved.id,
      userId: saved.userId,
      deviceId: saved.deviceId,
      score: saved.score,
      status: saved.status,
      riskLevel,
      factors: saved.factors,
      factorDetails: saved.factors.map((f, idx) => ({
        ruleId: `FACTOR_${idx + 1}`,
        impact: status === 'PROTECTED' ? 0 : -10,
        label: f,
        detail: f,
      })),
      recommendations: saved.recommendations,
      recommendedAction:
        saved.recommendations[0] ?? 'Your personal security posture is strong.',
      updatedAt: saved.updatedAt.toISOString(),
    };
  }

  /**
   * Simulates a clearly labeled Demo Security Event (Prompt 0008 Part 13)
   * so users can test the complete event -> risk -> notification -> timeline -> audit pipeline.
   */
  async triggerDemoScenario(
    userId: string,
    scenario: DemoEventScenario,
    deviceId?: string | null
  ): Promise<IngestSecurityEventResult> {
    const devices = await this.repository.listDevicesByUserId(userId);
    const fallbackDevice = deviceId
      ? devices.find((d) => d.device.id === deviceId)?.device
      : devices[0]?.device;

    const targetDeviceId = fallbackDevice?.id ?? null;
    const targetDeviceName = fallbackDevice?.name ?? 'Primary Device';

    switch (scenario) {
      case 'NEW_SIGN_IN_ALERT':
        return this.ingestEvent({
          userId,
          deviceId: targetDeviceId,
          category: 'Authentication',
          type: 'SIGN_IN_FAILURE',
          severity: 'WARNING',
          source: 'WEB',
          title: 'Unrecognized sign-in attempt blocked (Demo)',
          description:
            'Simulation: An unrecognized sign-in attempt from a new browser location was blocked by VAJRA.',
          metadata: {
            demoSimulation: true,
            scenario: 'NEW_SIGN_IN_ALERT',
            locationHint: 'Frankfurt, DE (Simulated)',
          },
        });

      case 'DEVICE_CHECK_IN':
        if (targetDeviceId) {
          await this.repository.createDeviceHeartbeat({
            deviceId: targetDeviceId,
            connectivityStatus: 'ONLINE',
            batteryLevel: 92,
            charging: true,
            networkType: 'WIFI',
            osVersion: fallbackDevice?.osVersion ?? 'Verified OS',
            agentVersion: '1.4.0-demo',
            permissionSummary: 'Location & Recovery Ready',
            securitySummary: 'Hardware identity verified',
            locationPermissionGranted: true,
          });
        }
        return this.ingestEvent({
          userId,
          deviceId: targetDeviceId,
          category: 'Device',
          type: 'DEVICE_HEARTBEAT_RECEIVED',
          severity: 'PROTECTED',
          source: 'DEVICE',
          title: `Security check completed on ${targetDeviceName} (Demo)`,
          description: `Simulation: ${targetDeviceName} completed a verified heartbeat check-in with all protections active.`,
          metadata: {
            demoSimulation: true,
            scenario: 'DEVICE_CHECK_IN',
            batteryLevel: 92,
            networkType: 'WIFI',
          },
        });

      case 'SUSPICIOUS_LINK_DETECTED':
        return this.ingestEvent({
          userId,
          deviceId: targetDeviceId,
          category: 'ThreatCheck',
          type: 'THREATCHECK_HIGH_RISK',
          severity: 'HIGH',
          source: 'THREATCHECK',
          title: 'High-risk phishing link detected (Demo)',
          description:
            'Simulation: ThreatCheck identified a deceptive sign-in link attempting to impersonate a financial service.',
          metadata: {
            demoSimulation: true,
            scenario: 'SUSPICIOUS_LINK_DETECTED',
            inspectedDomain: 'secure-account-verify-alert.example',
            riskScore: 88,
          },
        });

      case 'LOST_MODE_SIMULATION':
        return this.ingestEvent({
          userId,
          deviceId: targetDeviceId,
          category: 'Recovery',
          type: 'LOST_MODE_ENABLED',
          severity: 'HIGH',
          source: 'RECOVERY',
          title: `Lost Mode rehearsal on ${targetDeviceName} (Demo)`,
          description: `Simulation: Lost Mode protection and lock-screen contact recovery were tested for ${targetDeviceName}.`,
          metadata: {
            demoSimulation: true,
            scenario: 'LOST_MODE_SIMULATION',
          },
        });

      case 'RECOVERY_MESSAGE_TEST':
      default:
        return this.ingestEvent({
          userId,
          deviceId: targetDeviceId,
          category: 'Recovery',
          type: 'RECOVERY_MESSAGE_DISPLAYED',
          severity: 'PROTECTED',
          source: 'RECOVERY',
          title: `Recovery message verified on ${targetDeviceName} (Demo)`,
          description: `Simulation: ${targetDeviceName} confirmed the return instructions message can be displayed on the lock screen.`,
          metadata: {
            demoSimulation: true,
            scenario: 'RECOVERY_MESSAGE_TEST',
          },
        });
    }
  }

  private shouldAuditEvent(type: SecurityEventType, severity: SecurityEventSeverity): boolean {
    if (severity === 'HIGH' || severity === 'CRITICAL' || severity === 'WARNING') {
      return true;
    }
    const alwaysAudited: SecurityEventType[] = [
      'SIGN_IN_SUCCESS',
      'SIGN_IN_FAILURE',
      'MFA_ENABLED',
      'MFA_DISABLED',
      'DEVICE_APPROVED',
      'DEVICE_REVOKED',
      'DEVICE_COMPROMISED',
      'LOST_MODE_ENABLED',
      'LOST_MODE_DISABLED',
      'COMMAND_CREATED',
      'COMMAND_COMPLETED',
      'COMMAND_FAILED',
    ];
    return alwaysAudited.includes(type);
  }

  private async appendAuditEntry(event: SecurityEventEntity): Promise<void> {
    try {
      await this.repository.appendAuditEvent({
        actorUserId: event.userId,
        actorDeviceId: event.deviceId,
        eventType: 'SECURITY_EVENT_RECORDED',
        metadata: {
          securityEventId: event.id,
          securityEventType: event.type,
          category: event.category,
          severity: event.severity,
          source: event.source,
          title: event.title,
        },
        timestamp: event.receivedAt,
      });
    } catch {
      // Non-fatal in case of concurrent sequence write in memory fallback
    }
  }

  toDto(entity: SecurityEventEntity, deviceName?: string | null): SecurityEventDto {
    return {
      id: entity.id,
      userId: entity.userId,
      deviceId: entity.deviceId,
      deviceName: deviceName ?? null,
      category: entity.category as SecurityEventCategory,
      type: entity.type as SecurityEventType,
      severity: entity.severity as SecurityEventSeverity,
      occurredAt: entity.occurredAt.toISOString(),
      receivedAt: entity.receivedAt.toISOString(),
      title: entity.title,
      description: entity.description,
      metadata: entity.metadata,
      source: entity.source as SecurityEventSource,
      correlationId: entity.correlationId,
    };
  }
}
