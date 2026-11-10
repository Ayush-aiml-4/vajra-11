/**
 * VAJRA — Prompt 0007
 * Notifications, Security Activity, ThreatCheck Inspection & Unified Device Control Routes
 *
 * Implements:
 * 1. GET /api/notifications — List user notifications + unread counts
 * 2. POST /api/notifications/:id/read — Mark notification as read (ownership enforced)
 * 3. POST /api/notifications/read-all — Mark all user notifications as read
 * 4. POST /api/notifications/:id/dismiss — Dismiss notification (ownership enforced)
 * 5. GET /api/activity — Unified, human-readable Security Activity timeline with category/device/severity filtering
 * 6. POST /api/threatcheck/inspect — Inspect a website link, record Security Activity, and generate a notification on suspicious/high-risk links
 * 7. POST /api/devices/:id/actions — Execute an allowlisted device action (REQUEST_LOCATION, RING_DEVICE, DISPLAY_RECOVERY_MESSAGE, ENABLE_LOST_MODE, DISABLE_LOST_MODE, REQUEST_DEVICE_STATUS)
 * 8. GET /api/devices/:id/actions — List recent device actions for an owned device
 *
 * Security Rules Enforced:
 * - Strict authenticated user ownership checks (returns 404 on cross-user access)
 * - Strict allowlist validation on device actions (rejects arbitrary commands/shell/scripts)
 * - Sanitizes all user-supplied text (e.g., recovery messages, URLs)
 * - Never exposes raw internal stack traces, secrets, or tokens
 */

import { Router, Request, Response } from 'express';
import {
  ALLOWLISTED_DEVICE_ACTIONS,
  AllowlistedDeviceActionType,
  CommandResultDto,
  CommandStatus,
  DEMO_EVENT_SCENARIOS,
  DemoEventScenario,
  DeviceActionRecordDto,
  DeviceHeartbeatDto,
  DeviceLocationSummaryDto,
  NotificationCategory,
  NotificationItemDto,
  NotificationSeverity,
  NotificationType,
  SecurityActivityCategory,
  SecurityActivityItemDto,
} from '../../../packages/shared-types/src/index.ts';
import { isValidDeviceLifecycleTransition } from '../../../packages/security/src/node.ts';
import {
  CommandResultEntity,
  DeviceEntity,
  DeviceHeartbeatEntity,
  IdentityRepository,
  isLegalCommandTransition,
  NotificationEntity,
  RemoteCommandEntity,
  ThreatCheckEntity,
} from '../db/repository.ts';
import {
  requireAuthenticatedUser,
  requireStepUp,
  sessionHasValidStepUp,
  acceptableStepUpScopes,
  StepUpScope,
  STEP_UP_SCOPES,
} from '../auth/middleware.ts';
import {
  requireTrustedDevice,
  toSafeDeviceDto,
  assertDeviceRouteBinding,
  normalizeReportedDeviceName,
  getNeutralDeviceFallbackName,
} from '../devices/routes.ts';
import { SecurityEventEngine } from '../events/engine.ts';
import {
  analyzeThreatCheckUrl,
  escapeCsvCellSafe,
} from '../threatcheck/urlSafety.ts';

export interface NotificationAndActivityRouterOptions {
  repository: IdentityRepository;
}

export function sanitizePlainText(raw: unknown, maxLen = 240): string {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/[<>"'`\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen);
}

/**
 * Authoritative server-side capability matrix aligned with:
 * - `apps/windows-agent/src/Commands/CommandCapabilityMatrix.cs` (`REQUEST_DEVICE_STATUS` only)
 * - `apps/android/app/src/main/java/com/vajra/companion/commands/CommandCapabilityMatrix.kt`
 *   (`REQUEST_DEVICE_STATUS` and `RING_DEVICE` only)
 *
 * Server-side account lifecycle flags (`ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`) are valid only on
 * `POST /api/devices/:id/actions` (never as queued Plane-2 physical commands on `/commands`),
 * and unimplemented physical capabilities (`REQUEST_LOCATION`, `DISPLAY_RECOVERY_MESSAGE`, and
 * `RING_DEVICE` on non-Android platforms) are rejected server-side before step-up consumption or DB writes.
 */
export function validateActionCapabilityForDevice(
  actionType: AllowlistedDeviceActionType,
  deviceType: string,
  routeKind: 'commands' | 'actions'
): { supported: true } | { supported: false; reason: string } {
  const normalizedPlatform = String(deviceType ?? '').trim().toUpperCase();

  if (actionType === 'REQUEST_DEVICE_STATUS') {
    if (normalizedPlatform === 'WINDOWS' || normalizedPlatform === 'ANDROID') {
      return { supported: true };
    }
    return {
      supported: false,
      reason: `REQUEST_DEVICE_STATUS is not supported for platform ${normalizedPlatform || 'UNKNOWN'}.`,
    };
  }

  if (actionType === 'RING_DEVICE') {
    if (normalizedPlatform === 'ANDROID') {
      return { supported: true };
    }
    return {
      supported: false,
      reason:
        'RING_DEVICE is only supported by the Android companion app. Windows background services do not perform speaker playback.',
    };
  }

  if (actionType === 'ENABLE_LOST_MODE' || actionType === 'DISABLE_LOST_MODE') {
    if (routeKind === 'commands') {
      return {
        supported: false,
        reason: `${actionType} is a server-side VAJRA account recovery state transition, not an executable Plane-2 agent command.`,
      };
    }
    if (normalizedPlatform === 'WINDOWS' || normalizedPlatform === 'ANDROID') {
      return { supported: true };
    }
    return {
      supported: false,
      reason: `${actionType} is not supported for platform ${normalizedPlatform || 'UNKNOWN'}.`,
    };
  }

  if (actionType === 'REQUEST_LOCATION') {
    return {
      supported: false,
      reason:
        'Physical device location collection (REQUEST_LOCATION) is not implemented in the Windows or Android agent and cannot be queued or marked completed.',
    };
  }

  if (actionType === 'DISPLAY_RECOVERY_MESSAGE') {
    return {
      supported: false,
      reason:
        'Physical OS lock-screen message display (DISPLAY_RECOVERY_MESSAGE) is not implemented in the Windows or Android agent and cannot be queued or marked completed.',
    };
  }

  return {
    supported: false,
    reason: `Action ${actionType} is not supported on platform ${normalizedPlatform || 'UNKNOWN'}.`,
  };
}

export function toNotificationDto(entity: NotificationEntity): NotificationItemDto {
  return {
    id: entity.id,
    userId: entity.userId,
    type: entity.type as NotificationType,
    severity: (entity.severity as NotificationSeverity) || 'INFO',
    category: (entity.category as NotificationCategory) || 'Security',
    title: entity.title,
    message: entity.message,
    createdAt: entity.createdAt.toISOString(),
    readAt: entity.readAt ? entity.readAt.toISOString() : null,
    dismissedAt: entity.dismissedAt ? entity.dismissedAt.toISOString() : null,
    relatedDeviceId: entity.relatedDeviceId,
    relatedDeviceName: entity.relatedDeviceName,
    relatedEventId: entity.relatedEventId,
    actionLabel: entity.actionLabel,
    actionTarget: entity.actionTarget,
    metadata: entity.metadata ?? {},
  };
}

export function toCommandResultDto(entity: CommandResultEntity): CommandResultDto {
  return {
    id: entity.id,
    commandId: entity.commandId,
    deviceId: entity.deviceId,
    status: entity.status as 'COMPLETED' | 'FAILED',
    receivedAt: entity.receivedAt.toISOString(),
    completedAt: entity.completedAt ? entity.completedAt.toISOString() : null,
    errorCode: entity.errorCode,
    safeMessage: entity.safeMessage,
    deviceTimestamp: entity.deviceTimestamp ? entity.deviceTimestamp.toISOString() : null,
    resultMetadata: entity.resultMetadata ?? {},
  };
}

export function toDeviceHeartbeatDto(entity: DeviceHeartbeatEntity): DeviceHeartbeatDto {
  return {
    id: entity.id,
    deviceId: entity.deviceId,
    connectivityStatus: entity.connectivityStatus,
    batteryLevel: entity.batteryLevel,
    charging: entity.charging,
    networkType: entity.networkType,
    osVersion: entity.osVersion,
    agentVersion: entity.agentVersion,
    permissionSummary: entity.permissionSummary,
    securitySummary: entity.securitySummary,
    locationPermissionGranted: entity.locationPermissionGranted,
    receivedAt: entity.receivedAt.toISOString(),
  };
}

export interface DeviceBatteryReadingDto {
  timestamp: string;
  time: string;
  batteryLevel: number;
  charging: boolean;
}

/**
 * Maps genuinely persisted device heartbeats to battery telemetry readings.
 * Never synthesizes or fabricates historical readings.
 */
export function mapHeartbeatsToBatteryReadings(
  heartbeats: DeviceHeartbeatEntity[]
): DeviceBatteryReadingDto[] {
  return heartbeats
    .filter(
      (hb) =>
        typeof hb.batteryLevel === 'number' &&
        !Number.isNaN(hb.batteryLevel) &&
        hb.batteryLevel >= 0 &&
        hb.batteryLevel <= 100
    )
    .map((hb) => ({
      timestamp: hb.receivedAt.toISOString(),
      time: hb.receivedAt.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }),
      batteryLevel: hb.batteryLevel!,
      charging: Boolean(hb.charging),
    }));
}

export function toDeviceActionDto(
  entity: RemoteCommandEntity,
  deviceName: string,
  result?: CommandResultEntity | null
): DeviceActionRecordDto {
  const locationSnapshot = entity.payloadSummary?.locationSnapshot as
    | DeviceLocationSummaryDto
    | undefined;

  return {
    id: entity.id,
    deviceId: entity.deviceId,
    deviceName,
    issuerUserId: entity.issuerUserId,
    actionType: entity.actionType as AllowlistedDeviceActionType,
    status: entity.status as CommandStatus,
    statusMessage: entity.statusMessage,
    payloadSummary: entity.payloadSummary ?? {},
    requestedAt: entity.requestedAt.toISOString(),
    deliveredAt: entity.deliveredAt ? entity.deliveredAt.toISOString() : null,
    acknowledgedAt: entity.acknowledgedAt ? entity.acknowledgedAt.toISOString() : null,
    completedAt: entity.completedAt ? entity.completedAt.toISOString() : null,
    expiresAt: entity.expiresAt ? entity.expiresAt.toISOString() : null,
    ...(entity.nonce ? { nonce: entity.nonce } : {}),
    ...(locationSnapshot ? { locationSnapshot } : {}),
    ...(result !== undefined ? { result: result ? toCommandResultDto(result) : null } : {}),
  };
}

/**
 * Translates an AuditChainEntry into a rich, human-readable SecurityActivityItemDto.
 * Never exposes internal cryptographic identifiers, database tables, or raw hashes.
 */
export function mapAuditEntryToSecurityActivity(params: {
  id: string;
  actorUserId: string | null;
  eventType: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  deviceLookup: Map<string, string>;
}): SecurityActivityItemDto {
  const { id, actorUserId, eventType, timestamp, metadata, deviceLookup } = params;
  const rawDeviceId =
    typeof metadata?.deviceId === 'string' ? metadata.deviceId : null;
  const resolvedDeviceName =
    typeof metadata?.deviceName === 'string' && metadata.deviceName.trim().length > 0
      ? metadata.deviceName.trim()
      : rawDeviceId && deviceLookup.has(rawDeviceId)
      ? deviceLookup.get(rawDeviceId)!
      : null;

  const deviceLabel = resolvedDeviceName ?? 'Your device';

  switch (eventType) {
    case 'ACCOUNT_CREATED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'PROTECTED',
        title: 'VAJRA account created',
        subtitle: 'Web Console · Protected',
        description: 'Your personal security console was initialized and secured.',
        timestamp,
        metadata,
      };
    case 'LOGIN_SUCCESS':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'INFO',
        title: 'Signed in to VAJRA',
        subtitle: metadata?.mfaVerified
          ? 'Web Console · Two-step verified'
          : 'Web Console · Verified session',
        description: 'A new session was authenticated on your personal security console.',
        timestamp,
        metadata,
      };
    case 'LOGIN_FAILURE':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'WARNING',
        title: 'Failed sign-in attempt blocked',
        subtitle: 'Account Protection · Blocked',
        description: 'An incorrect password attempt was prevented from accessing your account.',
        timestamp,
        metadata,
      };
    case 'ACCOUNT_LOCKED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'HIGH',
        title: 'Sign-in protection activated',
        subtitle: 'Account Protection · Temporary pause',
        description: 'Account sign-in was temporarily paused after repeated failed attempts.',
        timestamp,
        metadata,
      };
    case 'LOGOUT':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'INFO',
        title: 'Signed out safely',
        subtitle: 'Web Console',
        description: 'Your security console session was closed.',
        timestamp,
        metadata,
      };
    case 'MFA_SETUP_STARTED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'INFO',
        title: 'Two-step verification started',
        subtitle: 'Account Security',
        description: 'Authenticator app setup was initiated for your account.',
        timestamp,
        metadata,
      };
    case 'MFA_ENABLED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'PROTECTED',
        title: 'Two-step verification enabled',
        subtitle: 'Account Security · Protected',
        description:
          'Your account is now protected with an authenticator app and backup recovery codes.',
        timestamp,
        metadata,
      };
    case 'MFA_DISABLED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'ATTENTION',
        title: 'Two-step verification turned off',
        subtitle: 'Account Security · Review recommended',
        description: 'Authenticator verification was turned off for your account.',
        timestamp,
        metadata,
      };
    case 'MFA_VERIFICATION_FAILURE':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'WARNING',
        title: 'Verification code rejected',
        subtitle: 'Account Security',
        description: 'An invalid two-step verification code was entered.',
        timestamp,
        metadata,
      };
    case 'RECOVERY_CODE_USED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Recovery',
        severity: 'ATTENTION',
        title: 'Recovery code used to sign in',
        subtitle: 'Account Recovery',
        description: 'One of your single-use backup recovery codes was used to sign in.',
        timestamp,
        metadata,
      };
    case 'RECOVERY_CODES_REGENERATED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Recovery',
        severity: 'PROTECTED',
        title: 'Backup recovery codes refreshed',
        subtitle: 'Account Recovery · Updated',
        description: 'A fresh set of backup recovery codes was created and older codes were retired.',
        timestamp,
        metadata,
      };
    case 'PASSWORD_CHANGED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'PROTECTED',
        title: 'Account password updated',
        subtitle: 'Account Security · Protected',
        description: 'Your password was updated and other active sessions were signed out.',
        timestamp,
        metadata,
      };
    case 'SESSION_REVOKED':
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'Authentication',
        severity: 'INFO',
        title: 'Other sessions signed out',
        subtitle: 'Session Protection',
        description: 'Active sessions on other browsers were closed to protect your account.',
        timestamp,
        metadata,
      };
    case 'DEVICE_ENROLLMENT_INITIATED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Device',
        severity: 'INFO',
        title: `Connection started for ${deviceLabel}`,
        subtitle: `${deviceLabel} · Setup in progress`,
        description: `A one-time connection code was created to link ${deviceLabel}.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_KEY_SUBMITTED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Device',
        severity: 'ATTENTION',
        title: `${deviceLabel} waiting for your approval`,
        subtitle: `${deviceLabel} · Ready to confirm`,
        description: `${deviceLabel} verified its identity and is waiting for your approval.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ENROLLMENT_PROOF_FAILURE':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Security',
        severity: 'WARNING',
        title: 'Unverified device connection blocked',
        subtitle: `${deviceLabel} · Blocked`,
        description: 'A device attempted to connect without valid identity verification.',
        timestamp,
        metadata,
      };
    case 'DEVICE_ENROLLED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Device',
        severity: 'PROTECTED',
        title: `${deviceLabel} connected and protected`,
        subtitle: `${deviceLabel} · Protected`,
        description: `You approved ${deviceLabel} and added it to your protected devices.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_KEY_ROTATED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Security',
        severity: 'PROTECTED',
        title: 'Device security credentials refreshed',
        subtitle: `${deviceLabel} · Protected`,
        description: `${deviceLabel} automatically refreshed its security credentials.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_AUTH_VERIFIED':
    case 'DEVICE_ACTION_STATUS_CHECKED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Security',
        severity: 'PROTECTED',
        title: 'Security check completed',
        subtitle: `${deviceLabel} · Healthy`,
        description: `${deviceLabel} checked in and confirmed all security protections are active.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_COMPROMISED_FLAGGED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Security',
        severity: 'CRITICAL',
        title: `${deviceLabel} marked for review`,
        subtitle: `${deviceLabel} · Needs attention`,
        description: `Trusted access for ${deviceLabel} was paused while you review its security.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_REVOKED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Device',
        severity: 'WARNING',
        title: `${deviceLabel} disconnected`,
        subtitle: `${deviceLabel} · Disconnected`,
        description: `Access for ${deviceLabel} was permanently removed from your account.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_DECOMMISSIONED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Device',
        severity: 'INFO',
        title: `${deviceLabel} archived`,
        subtitle: `${deviceLabel} · Archived`,
        description: `${deviceLabel} was moved to your archived devices.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ACTION_LOCATION_REQUESTED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Recovery',
        severity: 'INFO',
        title: 'Location requested',
        subtitle: `${deviceLabel} · ${
          typeof metadata?.regionSummary === 'string'
            ? metadata.regionSummary
            : 'Location updated'
        }`,
        description:
          typeof metadata?.locationDetail === 'string'
            ? metadata.locationDetail
            : `Updated last known location summary for ${deviceLabel}.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ACTION_RING_REQUESTED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Recovery',
        severity: 'ATTENTION',
        title: `Ring alert sent to ${deviceLabel}`,
        subtitle: `${deviceLabel} · Audible alert`,
        description:
          typeof metadata?.statusMessage === 'string'
            ? metadata.statusMessage
            : `Requested a high-volume audible recovery chime on ${deviceLabel}.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ACTION_RECOVERY_MESSAGE_SENT':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Recovery',
        severity: 'ATTENTION',
        title: `Recovery message prepared for ${deviceLabel}`,
        subtitle: `${deviceLabel} · Recovery display`,
        description:
          typeof metadata?.messageTitle === 'string'
            ? `Recovery message "${metadata.messageTitle}" queued for display on ${deviceLabel}.`
            : `Prepared a custom return message for ${deviceLabel}.`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ACTION_LOST_MODE_ENABLED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Recovery',
        severity: 'HIGH',
        title: `Lost Mode enabled on ${deviceLabel}`,
        subtitle: `${deviceLabel} · Account Lost Mode`,
        description: `Recorded server-side Lost Mode and owner recovery contact notes in VAJRA for ${deviceLabel} (physical OS screen lock and live GPS tracking are not performed by the agent).`,
        timestamp,
        metadata,
      };
    case 'DEVICE_ACTION_LOST_MODE_DISABLED':
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Recovery',
        severity: 'PROTECTED',
        title: `Lost Mode turned off on ${deviceLabel}`,
        subtitle: `${deviceLabel} · Protected`,
        description: `${deviceLabel} was restored to standard protected status.`,
        timestamp,
        metadata,
      };
    case 'THREATCHECK_INSPECTED': {
      const verdict =
        typeof metadata?.verdict === 'string' ? metadata.verdict : 'LOW RISK';
      const hostname =
        typeof metadata?.hostname === 'string' ? metadata.hostname : 'website link';
      const isHigh = verdict === 'HIGH RISK';
      const isSuspicious = verdict === 'SUSPICIOUS';
      return {
        id,
        userId: actorUserId,
        deviceId: null,
        deviceName: null,
        category: 'ThreatCheck',
        severity: isHigh ? 'HIGH' : isSuspicious ? 'WARNING' : 'PROTECTED',
        title:
          isHigh
            ? 'High-risk link flagged'
            : isSuspicious
            ? 'Suspicious link inspected'
            : 'Website link inspected',
        subtitle: `ThreatCheck · ${hostname} · ${verdict}`,
        description:
          typeof metadata?.summary === 'string'
            ? metadata.summary
            : `Checked ${hostname} for deceptive or unsafe link characteristics.`,
        timestamp,
        metadata,
      };
    }
    default:
      return {
        id,
        userId: actorUserId,
        deviceId: rawDeviceId,
        deviceName: resolvedDeviceName,
        category: 'Security',
        severity: 'PROTECTED',
        title: 'Security check completed',
        subtitle: resolvedDeviceName ? `${resolvedDeviceName} · Protected` : 'VAJRA Console',
        description: 'VAJRA verified your account and device protection status.',
        timestamp,
        metadata,
      };
  }
}

/**
 * Computes an honest, platform-aware location summary for a device.
 * Never fabricates GPS coordinates, ~25m precision, or synthetic check-in timestamps.
 */
export function buildDeviceLocationSummary(
  device: DeviceEntity,
  _now: Date,
  latestHeartbeat?: DeviceHeartbeatEntity | null
): DeviceLocationSummaryDto {
  const lastVerifiedTimestamp =
    latestHeartbeat?.receivedAt?.toISOString() ??
    (device.lastHeartbeatAt ? device.lastHeartbeatAt.toISOString() : null);

  const hasActiveCheckIn =
    Boolean(lastVerifiedTimestamp) &&
    device.connectivityStatus === 'ONLINE' &&
    device.lifecycleState !== 'REVOKED' &&
    device.lifecycleState !== 'DECOMMISSIONED' &&
    device.lifecycleState !== 'ENROLLMENT_PENDING';

  if (!hasActiveCheckIn) {
    return {
      accuracyMode: 'UNAVAILABLE',
      label: 'Awaiting signed device check-in',
      regionSummary:
        device.lifecycleState === 'ENROLLMENT_PENDING'
          ? 'Complete device pairing and owner approval before location checks can run'
          : 'No active check-in yet — location status updates only when the companion agent reports in',
      sourceLabel:
        device.deviceType === 'ANDROID'
          ? 'Android companion permission check (awaiting connection)'
          : 'Network check-in status (awaiting connection)',
      updatedAt: lastVerifiedTimestamp,
    };
  }

  if (device.deviceType === 'ANDROID') {
    const locationGranted = latestHeartbeat?.locationPermissionGranted === true;
    return {
      accuracyMode: locationGranted ? 'PERMISSION_AVAILABLE' : 'UNAVAILABLE',
      label: locationGranted
        ? 'Permission-gated Android location ready'
        : 'Android location permission not granted',
      regionSummary: locationGranted
        ? 'Location permission reported by Android companion · Coordinates are only recorded from signed device receipts'
        : 'Grant foreground location permission in the VAJRA Android app to allow recovery checks',
      sourceLabel: 'Signed Android companion heartbeat',
      updatedAt: lastVerifiedTimestamp,
    };
  }

  const netLabel =
    latestHeartbeat?.networkType && latestHeartbeat.networkType !== 'UNKNOWN'
      ? latestHeartbeat.networkType.toLowerCase()
      : 'network';

  return {
    accuracyMode: 'APPROXIMATE_NETWORK',
    label: 'Check-in connectivity summary only',
    regionSummary: `Connected via ${netLabel} · Windows agent does not collect GPS coordinates`,
    sourceLabel: 'Signed Windows agent heartbeat',
    updatedAt: lastVerifiedTimestamp,
  };
}

/**
 * Maximum DeviceHeartbeat rows read for GET /api/devices/:id/battery-history.
 * The 24-hour lower bound is computed on the server. This route always passes
 * this limit; repository implementations clamp a requested take to at most 200.
 */
export const BATTERY_HISTORY_RESULT_LIMIT = 100;

export function createNotificationAndActivityRouter(
  options: NotificationAndActivityRouterOptions
): Router {
  const router = Router();
  const repo = options.repository;
  const eventEngine = new SecurityEventEngine(repo);

  /**
   * GET /api/notifications
   * Lists active notifications for the authenticated user, ordered newest first.
   */
  router.get(
    '/notifications',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const includeDismissed = req.query.includeDismissed === 'true';
        const items = await repo.listNotificationsByUserId(ctx.user.id, {
          includeDismissed,
          limit: 50,
        });

        const dtos = items.map(toNotificationDto);
        const unreadCount = dtos.filter((n) => !n.readAt && !n.dismissedAt).length;

        res.status(200).json({
          notifications: dtos,
          unreadCount,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load notifications.' },
        });
      }
    }
  );

  /**
   * POST /api/notifications/read-all
   * Marks all unread notifications for the authenticated user as read.
   */
  router.post(
    '/notifications/read-all',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const updatedCount = await repo.markAllNotificationsRead({
          userId: ctx.user.id,
        });

        res.status(200).json({
          updatedCount,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to mark notifications as read.' },
        });
      }
    }
  );

  /**
   * POST /api/notifications/:id/read
   * Marks a single owned notification as read. Returns 404 if not owned by user.
   */
  router.post(
    '/notifications/:id/read',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const notificationId = String(req.params.id ?? '').trim();
        const updated = await repo.markNotificationRead({
          notificationId,
          userId: ctx.user.id,
        });

        if (!updated) {
          res.status(404).json({
            error: { code: 'NOTIFICATION_NOT_FOUND', message: 'Notification not found.' },
          });
          return;
        }

        res.status(200).json({
          notification: toNotificationDto(updated),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to update notification.' },
        });
      }
    }
  );

  /**
   * POST /api/notifications/:id/dismiss
   * Dismisses a single owned notification. Returns 404 if not owned by user.
   */
  router.post(
    '/notifications/:id/dismiss',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const notificationId = String(req.params.id ?? '').trim();
        const updated = await repo.dismissNotification({
          notificationId,
          userId: ctx.user.id,
        });

        if (!updated) {
          res.status(404).json({
            error: { code: 'NOTIFICATION_NOT_FOUND', message: 'Notification not found.' },
          });
          return;
        }

        res.status(200).json({
          notification: toNotificationDto(updated),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to dismiss notification.' },
        });
      }
    }
  );

  /**
   * GET /api/activity
   * Returns the authenticated user's unified Security Activity timeline with optional
   * category, deviceId, and severity filters.
   */
  router.get(
    '/activity',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const categoryFilter =
          typeof req.query.category === 'string' && req.query.category !== 'All'
            ? (req.query.category as SecurityActivityCategory)
            : null;
        const deviceIdFilter =
          typeof req.query.deviceId === 'string' && req.query.deviceId.trim().length > 0
            ? req.query.deviceId.trim()
            : null;
        const severityFilter =
          typeof req.query.severity === 'string' && req.query.severity.trim().length > 0
            ? req.query.severity.trim().toUpperCase()
            : null;

        const [auditEntries, securityEvents, userDevices] = await Promise.all([
          repo.listAuditEvents({
            actorUserId: ctx.user.id,
            limit: 80,
          }),
          repo.listSecurityEventsByUserId(ctx.user.id, { limit: 80 }),
          repo.listDevicesByUserId(ctx.user.id, { includeDecommissioned: true }),
        ]);

        const deviceLookup = new Map<string, string>();
        for (const { device } of userDevices) {
          deviceLookup.set(device.id, device.name);
        }

        const correlatedAuditIds = new Set(
          securityEvents
            .map((ev) => ev.correlationId)
            .filter((cid): cid is string => typeof cid === 'string' && cid.length > 0)
        );

        const mappedAuditActivities = auditEntries
          .filter(
            (entry) =>
              entry.eventType !== 'SECURITY_EVENT_RECORDED' &&
              !correlatedAuditIds.has(entry.id)
          )
          .map((entry) =>
            mapAuditEntryToSecurityActivity({
              id: entry.id,
              actorUserId: entry.actorUserId,
              eventType: entry.eventType,
              timestamp: entry.timestamp,
              metadata: entry.metadata,
              deviceLookup,
            })
          );

        const mappedSecurityEvents: SecurityActivityItemDto[] = securityEvents.map((ev) => {
          const devName = ev.deviceId ? deviceLookup.get(ev.deviceId) ?? null : null;
          const mappedCategory: SecurityActivityCategory =
            ev.category === 'Account'
              ? 'Authentication'
              : ev.category === 'Command'
              ? 'Recovery'
              : ev.category === 'Network'
              ? 'Device'
              : (ev.category as SecurityActivityCategory);
          return {
            id: ev.id,
            userId: ev.userId,
            deviceId: ev.deviceId,
            deviceName: devName,
            category: mappedCategory,
            severity: (ev.severity as NotificationSeverity) || 'INFO',
            title: ev.title,
            subtitle: devName ? `${devName} · ${ev.category}` : `VAJRA · ${ev.category}`,
            description: ev.description,
            timestamp: ev.occurredAt.toISOString(),
            metadata: ev.metadata,
          };
        });

        let activities = [...mappedSecurityEvents, ...mappedAuditActivities].sort(
          (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        );

        if (categoryFilter) {
          activities = activities.filter((a) => a.category === categoryFilter);
        }
        if (deviceIdFilter) {
          activities = activities.filter((a) => a.deviceId === deviceIdFilter);
        }
        if (severityFilter) {
          activities = activities.filter((a) => a.severity === severityFilter);
        }

        res.status(200).json({
          activities,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load security activity.' },
        });
      }
    }
  );

  /**
   * POST /api/threatcheck/inspect
   * Evaluates a submitted link using SSRF-aware lexical analysis, redacts query parameters and fragments,
   * persists ThreatCheck + ThreatIndicator records atomically, records sanitized AuditLog and SecurityEvent
   * entries, and creates an in-app notification if the link is SUSPICIOUS or HIGH RISK.
   */
  router.post(
    '/threatcheck/inspect',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const rawUrl = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
        if (!rawUrl || rawUrl.length > 2048) {
          res.status(400).json({
            error: {
              code: 'INVALID_URL',
              message: 'Please provide a valid website link to inspect (maximum 2048 characters).',
            },
          });
          return;
        }

        const deviceId =
          typeof req.body?.deviceId === 'string' && req.body.deviceId.trim().length > 0
            ? req.body.deviceId.trim()
            : null;

        if (deviceId) {
          const ownedDevice = await repo.findDeviceById(deviceId);
          if (!ownedDevice || ownedDevice.userId !== ctx.user.id) {
            res.status(404).json({
              error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
            });
            return;
          }
        }

        const evaluation = analyzeThreatCheckUrl(rawUrl);
        if (!evaluation.valid || !evaluation.analysisPreview) {
          res.status(400).json({
            error: {
              code: evaluation.errorCode ?? 'INVALID_URL',
              message:
                evaluation.errorMessage ?? 'Please provide a valid HTTP or HTTPS website link.',
            },
          });
          return;
        }

        const persistedCheck = await repo.createThreatCheck({
          userId: ctx.user.id,
          deviceId,
          submittedUrl: evaluation.submittedUrlRedacted!,
          normalizedDomain: evaluation.normalizedDomain!,
          verdict: evaluation.verdict!,
          riskScore: evaluation.riskScore ?? 0,
          summary: evaluation.summary!,
          recommendedGuidance: evaluation.recommendedGuidance!,
          source: 'WEB',
          indicators: evaluation.indicators ?? [],
        });

        const analysis = evaluation.analysisPreview;

        const auditEntry = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: deviceId,
          eventType: 'THREATCHECK_INSPECTED',
          metadata: {
            threatCheckId: persistedCheck.id,
            hostname: analysis.hostname,
            submittedUrlRedacted: persistedCheck.submittedUrl,
            normalizedDisplayUrl: analysis.normalizedDisplayUrl,
            verdict: analysis.verdict,
            classification: evaluation.classification,
            riskScore: persistedCheck.riskScore,
            restrictedDestination: Boolean(evaluation.restrictedDestination),
            indicatorCount: persistedCheck.indicators.length,
            summary: analysis.summary,
          },
        });

        const threatEventType =
          analysis.verdict === 'HIGH RISK'
            ? 'THREATCHECK_HIGH_RISK'
            : analysis.verdict === 'SUSPICIOUS'
            ? 'THREATCHECK_SUSPICIOUS'
            : 'THREATCHECK_LOW';

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          deviceId,
          category: 'ThreatCheck',
          type: threatEventType,
          severity:
            analysis.verdict === 'HIGH RISK'
              ? 'HIGH'
              : analysis.verdict === 'SUSPICIOUS'
              ? 'WARNING'
              : 'PROTECTED',
          source: 'THREATCHECK',
          title:
            analysis.verdict === 'HIGH RISK'
              ? `High-risk link flagged (${analysis.hostname})`
              : analysis.verdict === 'SUSPICIOUS'
              ? `Suspicious link inspected (${analysis.hostname})`
              : `Website link verified (${analysis.hostname})`,
          description: analysis.summary,
          metadata: {
            threatCheckId: persistedCheck.id,
            hostname: analysis.hostname,
            submittedUrlRedacted: persistedCheck.submittedUrl,
            verdict: analysis.verdict,
            classification: evaluation.classification,
            riskScore: persistedCheck.riskScore,
            restrictedDestination: Boolean(evaluation.restrictedDestination),
          },
          correlationId: auditEntry.id,
          skipNotificationPolicy: true,
          skipAuditRecord: true,
        });

        let createdNotification: NotificationItemDto | null = null;
        if (analysis.verdict === 'HIGH RISK' || analysis.verdict === 'SUSPICIOUS') {
          const notif = await repo.createNotification({
            userId: ctx.user.id,
            type: 'THREATCHECK_COMPLETED',
            severity: analysis.verdict === 'HIGH RISK' ? 'HIGH' : 'WARNING',
            category: 'Needs Attention',
            title:
              analysis.verdict === 'HIGH RISK'
                ? `High-risk link detected (${analysis.hostname})`
                : `Suspicious link flagged (${analysis.hostname})`,
            message: analysis.summary,
            relatedDeviceId: deviceId,
            relatedEventId: auditEntry.id,
            actionLabel: 'Review ThreatCheck',
            actionTarget: 'threat-check',
            metadata: {
              threatCheckId: persistedCheck.id,
              hostname: analysis.hostname,
              verdict: analysis.verdict,
              riskScore: persistedCheck.riskScore,
            },
          });
          createdNotification = toNotificationDto(notif);
        }

        res.status(200).json({
          analysis,
          threatCheck: {
            id: persistedCheck.id,
            userId: persistedCheck.userId,
            deviceId: persistedCheck.deviceId,
            submittedUrlRedacted: persistedCheck.submittedUrl,
            normalizedDomain: persistedCheck.normalizedDomain,
            verdict: persistedCheck.verdict,
            classification: evaluation.classification,
            riskScore: persistedCheck.riskScore,
            restrictedDestination: Boolean(evaluation.restrictedDestination),
            summary: persistedCheck.summary,
            recommendedGuidance: persistedCheck.recommendedGuidance,
            limitationsStatement: evaluation.limitationsStatement,
            source: persistedCheck.source,
            checkedAt: persistedCheck.checkedAt.toISOString(),
            indicators: persistedCheck.indicators.map((ind) => ({
              id: ind.id,
              code: ind.code,
              category: ind.category,
              severity: ind.severity,
              title: ind.title,
              explanation: ind.explanation,
              weight: ind.weight,
              createdAt: ind.createdAt.toISOString(),
            })),
          },
          activityId: auditEntry.id,
          notification: createdNotification,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to inspect website link.' },
        });
      }
    }
  );

  /**
   * GET /api/threatcheck/history
   * Returns paginated, user-scoped ThreatCheck records and structured ThreatIndicator lists.
   */
  router.get(
    '/threatcheck/history',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const rawLimit = req.query.limit !== undefined ? Number(req.query.limit) : 25;
        const rawOffset = req.query.offset !== undefined ? Number(req.query.offset) : 0;

        if (
          !Number.isInteger(rawLimit) ||
          rawLimit < 1 ||
          rawLimit > 100 ||
          !Number.isInteger(rawOffset) ||
          rawOffset < 0
        ) {
          res.status(400).json({
            error: {
              code: 'INVALID_PAGINATION',
              message: 'Pagination parameters must be valid integers (limit 1..100, offset >= 0).',
            },
          });
          return;
        }

        const verdictFilter =
          typeof req.query.verdict === 'string' && req.query.verdict.trim().length > 0
            ? req.query.verdict.trim().toUpperCase()
            : undefined;
        if (
          verdictFilter &&
          verdictFilter !== 'LOW RISK' &&
          verdictFilter !== 'SUSPICIOUS' &&
          verdictFilter !== 'HIGH RISK'
        ) {
          res.status(400).json({
            error: {
              code: 'INVALID_VERDICT_FILTER',
              message: 'Verdict filter must be LOW RISK, SUSPICIOUS, or HIGH RISK.',
            },
          });
          return;
        }

        const deviceIdFilter =
          typeof req.query.deviceId === 'string' && req.query.deviceId.trim().length > 0
            ? req.query.deviceId.trim()
            : undefined;
        if (deviceIdFilter) {
          const ownedDevice = await repo.findDeviceById(deviceIdFilter);
          if (!ownedDevice || ownedDevice.userId !== ctx.user.id) {
            res.status(404).json({
              error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
            });
            return;
          }
        }

        const { items, totalCount } = await repo.listThreatChecksByUserId(ctx.user.id, {
          deviceId: deviceIdFilter,
          verdict: verdictFilter,
          limit: rawLimit,
          offset: rawOffset,
        });

        res.status(200).json({
          checks: items.map((tc: ThreatCheckEntity) => ({
            id: tc.id,
            userId: tc.userId,
            deviceId: tc.deviceId,
            submittedUrlRedacted: tc.submittedUrl,
            normalizedDomain: tc.normalizedDomain,
            verdict: tc.verdict,
            riskScore: tc.riskScore,
            summary: tc.summary,
            recommendedGuidance: tc.recommendedGuidance,
            source: tc.source,
            checkedAt: tc.checkedAt.toISOString(),
            indicators: tc.indicators.map((ind) => ({
              id: ind.id,
              code: ind.code,
              category: ind.category,
              severity: ind.severity,
              title: ind.title,
              explanation: ind.explanation,
              weight: ind.weight,
              createdAt: ind.createdAt.toISOString(),
            })),
          })),
          pagination: {
            limit: rawLimit,
            offset: rawOffset,
            totalCount,
            hasMore: rawOffset + items.length < totalCount,
          },
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load ThreatCheck history.' },
        });
      }
    }
  );

  /**
   * GET /api/analytics/summary
   * Computes user-scoped security analytics derived strictly from persisted records
   * (devices, security events, notifications/alerts, ThreatCheck verdicts, risk scores, and commands).
   */
  router.get(
    '/analytics/summary',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const [
          userDevices,
          securityEvents,
          notifications,
          threatCheckHistory,
          remoteCommands,
          latestRisk,
        ] = await Promise.all([
          repo.listDevicesByUserId(ctx.user.id, { includeDecommissioned: true }),
          repo.listSecurityEventsByUserId(ctx.user.id, { limit: 100 }),
          repo.listNotificationsByUserId(ctx.user.id, { includeDismissed: true, limit: 100 }),
          repo.listThreatChecksByUserId(ctx.user.id, { limit: 100, offset: 0 }),
          repo.listAllRemoteCommandsByUserId(ctx.user.id, 100),
          repo.getLatestRiskAssessment(ctx.user.id),
        ]);

        // 1. Device counts by lifecycle status & platform
        const devicesByLifecycle: Record<string, number> = {};
        const devicesByPlatform: Record<string, number> = {};
        let hardwareBackedCount = 0;
        let totalDeviceRisk = 0;

        for (const { device, credentials } of userDevices) {
          devicesByLifecycle[device.lifecycleState] =
            (devicesByLifecycle[device.lifecycleState] ?? 0) + 1;
          devicesByPlatform[device.deviceType] =
            (devicesByPlatform[device.deviceType] ?? 0) + 1;
          totalDeviceRisk += device.currentRiskScore;
          if (credentials.some((c) => c.active && c.hardwareBacked)) {
            hardwareBackedCount++;
          }
        }

        const averageDeviceRiskScore =
          userDevices.length > 0 ? Math.round(totalDeviceRisk / userDevices.length) : 0;

        // 2. Security events by severity & category
        const eventsBySeverity: Record<string, number> = {};
        const eventsByCategory: Record<string, number> = {};
        for (const ev of securityEvents) {
          eventsBySeverity[ev.severity] = (eventsBySeverity[ev.severity] ?? 0) + 1;
          eventsByCategory[ev.category] = (eventsByCategory[ev.category] ?? 0) + 1;
        }

        // 3. Notifications / Alerts summary
        let unreadAlertsCount = 0;
        let highSeverityUnreadCount = 0;
        let dismissedAlertsCount = 0;
        for (const n of notifications) {
          if (n.dismissedAt) {
            dismissedAlertsCount++;
          } else if (!n.readAt) {
            unreadAlertsCount++;
            if (n.severity === 'HIGH' || n.severity === 'CRITICAL' || n.severity === 'WARNING') {
              highSeverityUnreadCount++;
            }
          }
        }

        // 4. ThreatCheck verdict counts & average risk score
        const threatChecksByVerdict: Record<string, number> = {
          'LOW RISK': 0,
          SUSPICIOUS: 0,
          'HIGH RISK': 0,
        };
        let totalThreatRisk = 0;
        for (const tc of threatCheckHistory.items) {
          threatChecksByVerdict[tc.verdict] = (threatChecksByVerdict[tc.verdict] ?? 0) + 1;
          totalThreatRisk += tc.riskScore;
        }
        const averageThreatCheckRiskScore =
          threatCheckHistory.items.length > 0
            ? Math.round(totalThreatRisk / threatCheckHistory.items.length)
            : 0;

        // 5. Remote commands by status & actionType
        const commandsByStatus: Record<string, number> = {};
        const commandsByActionType: Record<string, number> = {};
        for (const cmd of remoteCommands) {
          commandsByStatus[cmd.status] = (commandsByStatus[cmd.status] ?? 0) + 1;
          commandsByActionType[cmd.actionType] =
            (commandsByActionType[cmd.actionType] ?? 0) + 1;
        }

        res.status(200).json({
          summary: {
            generatedAt: new Date().toISOString(),
            dataSource: 'PERSISTED' as const,
            windowDescription:
              'User-scoped aggregates from persisted devices, security events (latest 100), notifications, ThreatCheck history, and remote commands (latest 100). Empty collections yield zero counts.',
            accountPosture: {
              currentScore: latestRisk ? latestRisk.score : 100,
              status: latestRisk ? latestRisk.status : 'PROTECTED',
              averageDeviceRiskScore,
            },
            devices: {
              totalCount: userDevices.length,
              hardwareBackedCount,
              byLifecycleState: devicesByLifecycle,
              byPlatform: devicesByPlatform,
            },
            securityEvents: {
              totalRecentCount: securityEvents.length,
              bySeverity: eventsBySeverity,
              byCategory: eventsByCategory,
            },
            alerts: {
              totalCount: notifications.length,
              openUnreadCount: unreadAlertsCount,
              highSeverityUnreadCount,
              dismissedCount: dismissedAlertsCount,
            },
            threatChecks: {
              totalCount: threatCheckHistory.totalCount,
              averageRiskScore: averageThreatCheckRiskScore,
              byVerdict: threatChecksByVerdict,
            },
            remoteCommands: {
              totalRecentCount: remoteCommands.length,
              byStatus: commandsByStatus,
              byActionType: commandsByActionType,
            },
          },
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to generate analytics summary.' },
        });
      }
    }
  );

  /**
   * GET /api/reports/export
   * Exports user-scoped security events, ThreatCheck inspections, and analytics summary
   * in JSON (?format=json) or formula-injection-safe CSV (?format=csv).
   */
  router.get(
    '/reports/export',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const format = String(req.query.format ?? 'json').trim().toLowerCase();
        if (format !== 'json' && format !== 'csv') {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_EXPORT_FORMAT',
              message: 'Export format must be either "json" or "csv".',
            },
          });
          return;
        }

        const rawLimit = req.query.limit !== undefined ? Number(req.query.limit) : 100;
        if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 200) {
          res.status(400).json({
            error: {
              code: 'INVALID_EXPORT_LIMIT',
              message: 'Export record limit must be an integer between 1 and 200.',
            },
          });
          return;
        }

        const [userDevices, securityEvents, threatChecks, remoteCommands, latestRisk] =
          await Promise.all([
            repo.listDevicesByUserId(ctx.user.id, { includeDecommissioned: true }),
            repo.listSecurityEventsByUserId(ctx.user.id, { limit: rawLimit }),
            repo.listThreatChecksByUserId(ctx.user.id, { limit: rawLimit, offset: 0 }),
            repo.listAllRemoteCommandsByUserId(ctx.user.id, rawLimit),
            repo.getLatestRiskAssessment(ctx.user.id),
          ]);

        const deviceNameMap = new Map<string, string>();
        for (const { device } of userDevices) {
          deviceNameMap.set(device.id, device.name);
        }

        await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'SECURITY_REPORT_EXPORTED',
          metadata: {
            format,
            eventRecordCount: securityEvents.length,
            threatCheckRecordCount: threatChecks.items.length,
            commandRecordCount: remoteCommands.length,
          },
        });

        const dateStamp = new Date().toISOString().slice(0, 10);

        if (format === 'json') {
          const payload = {
            reportMetadata: {
              platform: 'VAJRA Personal Security',
              generatedAt: new Date().toISOString(),
              ownerEmail: ctx.user.email,
              ownerDisplayName: ctx.user.displayName,
              recordLimit: rawLimit,
            },
            postureSummary: {
              riskScore: latestRisk ? latestRisk.score : 100,
              status: latestRisk ? latestRisk.status : 'PROTECTED',
              enrolledDeviceCount: userDevices.length,
              securityEventCount: securityEvents.length,
              threatCheckCount: threatChecks.totalCount,
              remoteCommandCount: remoteCommands.length,
            },
            devices: userDevices.map(({ device, credentials }) => ({
              id: device.id,
              name: device.name,
              deviceType: device.deviceType,
              lifecycleState: device.lifecycleState,
              connectivityStatus: device.connectivityStatus,
              currentRiskScore: device.currentRiskScore,
              hardwareBacked: credentials.some((c) => c.active && c.hardwareBacked),
              enrolledAt: device.enrolledAt ? device.enrolledAt.toISOString() : null,
              lastSeenAt: device.lastSeenAt ? device.lastSeenAt.toISOString() : null,
            })),
            securityEvents: securityEvents.map((ev) => ({
              id: ev.id,
              occurredAt: ev.occurredAt.toISOString(),
              category: ev.category,
              type: ev.type,
              severity: ev.severity,
              deviceName: ev.deviceId ? deviceNameMap.get(ev.deviceId) ?? null : null,
              title: ev.title,
              description: ev.description,
              source: ev.source,
            })),
            threatChecks: threatChecks.items.map((tc) => ({
              id: tc.id,
              checkedAt: tc.checkedAt.toISOString(),
              normalizedDomain: tc.normalizedDomain,
              submittedUrlRedacted: tc.submittedUrl,
              verdict: tc.verdict,
              riskScore: tc.riskScore,
              summary: tc.summary,
              indicatorCodes: tc.indicators.map((i) => i.code),
            })),
            remoteCommands: remoteCommands.map((cmd) => ({
              id: cmd.id,
              requestedAt: cmd.requestedAt.toISOString(),
              completedAt: cmd.completedAt ? cmd.completedAt.toISOString() : null,
              deviceName: deviceNameMap.get(cmd.deviceId) ?? null,
              actionType: cmd.actionType,
              status: cmd.status,
              statusMessage: cmd.statusMessage,
            })),
          };

          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.setHeader(
            'Content-Disposition',
            `attachment; filename="vajra-security-report-${dateStamp}.json"`
          );
          res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
          res.setHeader('Pragma', 'no-cache');
          res.status(200).send(JSON.stringify(payload, null, 2));
          return;
        }

        // CSV Export format: unified rows with formula-injection protection via escapeCsvCellSafe
        const csvHeaders = [
          'RecordType',
          'RecordId',
          'Timestamp',
          'CategoryOrAction',
          'SeverityOrVerdict',
          'DeviceName',
          'TargetOrDomain',
          'RiskScore',
          'Title',
          'Details',
        ];
        const csvRows: string[] = [csvHeaders.map((h) => escapeCsvCellSafe(h)).join(',')];

        for (const ev of securityEvents) {
          csvRows.push(
            [
              'SECURITY_EVENT',
              ev.id,
              ev.occurredAt.toISOString(),
              `${ev.category}:${ev.type}`,
              ev.severity,
              ev.deviceId ? deviceNameMap.get(ev.deviceId) ?? '' : '',
              ev.source,
              '',
              ev.title,
              ev.description,
            ]
              .map((cell) => escapeCsvCellSafe(cell))
              .join(',')
          );
        }

        for (const tc of threatChecks.items) {
          csvRows.push(
            [
              'THREAT_CHECK',
              tc.id,
              tc.checkedAt.toISOString(),
              'URL_INSPECTION',
              tc.verdict,
              tc.deviceId ? deviceNameMap.get(tc.deviceId) ?? '' : '',
              tc.submittedUrl,
              String(tc.riskScore),
              tc.normalizedDomain,
              tc.summary,
            ]
              .map((cell) => escapeCsvCellSafe(cell))
              .join(',')
          );
        }

        for (const cmd of remoteCommands) {
          csvRows.push(
            [
              'REMOTE_COMMAND',
              cmd.id,
              cmd.requestedAt.toISOString(),
              cmd.actionType,
              cmd.status,
              deviceNameMap.get(cmd.deviceId) ?? '',
              cmd.deviceId,
              '',
              cmd.actionType,
              cmd.statusMessage,
            ]
              .map((cell) => escapeCsvCellSafe(cell))
              .join(',')
          );
        }

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="vajra-security-report-${dateStamp}.csv"`
        );
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.status(200).send(csvRows.join('\n'));
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to export security report.' },
        });
      }
    }
  );

  /**
   * GET /api/devices/:id/actions
   * Lists recent allowlisted device actions for a user's device.
   * Returns 404 if device does not exist or belongs to another user.
   */
  router.get(
    '/devices/:id/actions',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        const [commands, latestHeartbeat] = await Promise.all([
          repo.listRemoteCommandsByDeviceId(device.id, ctx.user.id, 25),
          repo.getLatestDeviceHeartbeat(device.id),
        ]);
        const locationSummary = buildDeviceLocationSummary(device, new Date(), latestHeartbeat);

        res.status(200).json({
          actions: commands.map((cmd) => toDeviceActionDto(cmd, device.name)),
          locationSummary,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load device actions.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/actions
   * Dispatches an allowlisted device action for an owned device:
   * - REQUEST_LOCATION
   * - RING_DEVICE
   * - DISPLAY_RECOVERY_MESSAGE
   * - ENABLE_LOST_MODE
   * - DISABLE_LOST_MODE
   * - REQUEST_DEVICE_STATUS
   *
   * Rejects any non-allowlisted action with 400.
   * Returns 404 if the device does not exist or belongs to another user.
   */
  router.post(
    '/devices/:id/actions',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        const rawAction = String(req.body?.actionType ?? '').trim().toUpperCase();
        if (
          !ALLOWLISTED_DEVICE_ACTIONS.includes(
            rawAction as AllowlistedDeviceActionType
          )
        ) {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_DEVICE_ACTION',
              message:
                'This action is not permitted. Only allowlisted protection and recovery actions are supported.',
            },
          });
          return;
        }

        const actionType = rawAction as AllowlistedDeviceActionType;

        if (
          device.lifecycleState === 'REVOKED' ||
          device.lifecycleState === 'DECOMMISSIONED' ||
          device.lifecycleState === 'ENROLLMENT_PENDING' ||
          device.lifecycleState === 'COMPROMISED'
        ) {
          res.status(409).json({
            error: {
              code: 'DEVICE_NOT_READY_FOR_ACTIONS',
              message:
                device.lifecycleState === 'COMPROMISED'
                  ? 'This device is quarantined as compromised and cannot accept remote commands until reviewed.'
                  : 'This device must complete connection setup and remain active before recovery actions can be sent.',
            },
          });
          return;
        }

        // Enforce strict native-agent capability boundary before consuming MFA step-up or persisting records:
        // - Windows agent executes: REQUEST_DEVICE_STATUS
        // - Android companion executes: REQUEST_DEVICE_STATUS, RING_DEVICE
        // - ENABLE_LOST_MODE / DISABLE_LOST_MODE are explicit server-side account lifecycle transitions
        // - Physical location tracking and OS lock-screen message display are NOT implemented on agents
        const platformCapabilityCheck = validateActionCapabilityForDevice(
          actionType,
          device.deviceType,
          'actions'
        );
        if (!platformCapabilityCheck.supported) {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_COMMAND_FOR_PLATFORM',
              message: platformCapabilityCheck.reason,
            },
          });
          return;
        }

        // Sensitive actions require fresh MFA step-up bound to this session + scope
        const sensitiveScopes: Record<string, string> = {
          ENABLE_LOST_MODE: STEP_UP_SCOPES.ENABLE_LOST_MODE,
          DISABLE_LOST_MODE: STEP_UP_SCOPES.DISABLE_LOST_MODE,
          RING_DEVICE: STEP_UP_SCOPES.SENSITIVE_COMMAND,
          REQUEST_LOCATION: STEP_UP_SCOPES.SENSITIVE_COMMAND,
          DISPLAY_RECOVERY_MESSAGE: STEP_UP_SCOPES.SENSITIVE_COMMAND,
        };
        const requiredScope = sensitiveScopes[actionType];
        if (requiredScope && !sessionHasValidStepUp(ctx.session, requiredScope as any)) {
          res.status(403).json({
            error: {
              code: 'STEP_UP_REQUIRED',
              message:
                'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
              requiredScope,
            },
          });
          return;
        }

        const now = new Date();
        const latestHeartbeat = await repo.getLatestDeviceHeartbeat(device.id);
        // Device-execution actions remain QUEUED until a signed CommandResult arrives.
        // Server-side account recovery flags (ENABLE/DISABLE_LOST_MODE) update VAJRA account state only.
        let updatedDevice = device;
        let commandStatus: CommandStatus = CommandStatus.QUEUED;
        let statusMessage = '';
        let payloadSummary: Record<string, unknown> = {};
        let auditEventType = 'DEVICE_ACTION_STATUS_CHECKED';
        let notificationData: {
          type: NotificationType;
          severity: NotificationSeverity;
          category: NotificationCategory;
          title: string;
          message: string;
        } | null = null;

        if (actionType === 'REQUEST_LOCATION') {
          const locationSnapshot = buildDeviceLocationSummary(device, now, latestHeartbeat);
          payloadSummary = {
            locationSnapshot,
          };
          statusMessage = `Location request queued for ${device.name}. Awaiting signed device receipt.`;
          auditEventType = 'DEVICE_ACTION_LOCATION_REQUESTED';

          notificationData = {
            type: 'LOCATION_UPDATED',
            severity: 'INFO',
            category: 'Devices',
            title: `Location check queued for ${device.name}`,
            message: `${statusMessage} (${locationSnapshot.label}).`,
          };
        } else if (actionType === 'RING_DEVICE') {
          statusMessage = `Ring request queued for ${device.name}. Awaiting signed device receipt.`;
          payloadSummary = {
            platform: device.deviceType,
            durationSeconds: 60,
          };
          auditEventType = 'DEVICE_ACTION_RING_REQUESTED';

          notificationData = {
            type: 'DEVICE_RING_REQUESTED',
            severity: 'ATTENTION',
            category: 'Devices',
            title: `Ring alert queued for ${device.name}`,
            message: statusMessage,
          };
        } else if (actionType === 'DISPLAY_RECOVERY_MESSAGE') {
          const rawTitle = sanitizePlainText(
            req.body?.title ?? 'Lost Device — Please Return',
            80
          );
          const rawMessage = sanitizePlainText(
            req.body?.message ??
              'This device belongs to a verified owner. Please use the contact details below to return it.',
            240
          );
          const rawContact = sanitizePlainText(req.body?.contactInstruction ?? '', 120);

          if (!rawTitle || !rawMessage) {
            res.status(400).json({
              error: {
                code: 'INVALID_RECOVERY_MESSAGE',
                message: 'Please provide both a title and a recovery message.',
              },
            });
            return;
          }

          payloadSummary = {
            title: rawTitle,
            message: rawMessage,
            ...(rawContact ? { contactInstruction: rawContact } : {}),
            platformBehavior:
              device.deviceType === 'ANDROID'
                ? 'Recovery screen notice when permitted by Android'
                : 'Desktop recovery notice on next check-in',
          };

          statusMessage = `Recovery message "${rawTitle}" queued for ${device.name}. Awaiting signed device receipt.`;
          auditEventType = 'DEVICE_ACTION_RECOVERY_MESSAGE_SENT';

          notificationData = {
            type: 'RECOVERY_MESSAGE_SENT',
            severity: 'ATTENTION',
            category: 'Devices',
            title: `Recovery message queued for ${device.name}`,
            message: statusMessage,
          };
        } else if (actionType === 'ENABLE_LOST_MODE') {
          if (
            device.lifecycleState !== 'LOST' &&
            !isValidDeviceLifecycleTransition(device.lifecycleState, 'LOST')
          ) {
            res.status(409).json({
              error: {
                code: 'INVALID_LIFECYCLE_TRANSITION',
                message: `Cannot enable Lost Mode for a device in state ${device.lifecycleState}.`,
              },
            });
            return;
          }

          const messageTitle = sanitizePlainText(
            req.body?.title ?? 'This device is lost',
            80
          );
          const messageBody = sanitizePlainText(
            req.body?.message ??
              'This device is protected by VAJRA. Please contact the owner to arrange its return.',
            240
          );
          const contactInstruction = sanitizePlainText(
            req.body?.contactInstruction ?? '',
            120
          );

          const consumedLostStepUp = await repo.consumeStepUp({
            sessionId: ctx.session.id,
            acceptableScopes: acceptableStepUpScopes(requiredScope as StepUpScope),
            now,
          });
          if (!consumedLostStepUp) {
            res.status(403).json({
              error: {
                code: 'STEP_UP_REQUIRED',
                message:
                  'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
                requiredScope,
              },
            });
            return;
          }

          updatedDevice = await repo.updateDeviceState({
            deviceId: device.id,
            lifecycleState: 'LOST',
          });

          const locationSnapshot = buildDeviceLocationSummary(updatedDevice, now, latestHeartbeat);
          payloadSummary = {
            lostMode: true,
            executionScope: 'SERVER_ACCOUNT_STATE',
            physicalLockApplied: false,
            liveLocationTracking: false,
            title: messageTitle,
            message: messageBody,
            ...(contactInstruction ? { contactInstruction } : {}),
            locationSnapshot,
          };
          commandStatus = CommandStatus.COMPLETED;
          statusMessage = `Server-side Lost Mode recorded for ${device.name}. Owner recovery notes are saved in VAJRA; physical OS screen lock and live GPS tracking are not performed by the agent.`;
          auditEventType = 'DEVICE_ACTION_LOST_MODE_ENABLED';

          notificationData = {
            type: 'LOST_MODE_ENABLED',
            severity: 'HIGH',
            category: 'Needs Attention',
            title: `Lost Mode recorded for ${device.name}`,
            message: statusMessage,
          };
        } else if (actionType === 'DISABLE_LOST_MODE') {
          const consumedDisableStepUp = await repo.consumeStepUp({
            sessionId: ctx.session.id,
            acceptableScopes: acceptableStepUpScopes(requiredScope as StepUpScope),
            now,
          });
          if (!consumedDisableStepUp) {
            res.status(403).json({
              error: {
                code: 'STEP_UP_REQUIRED',
                message:
                  'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
                requiredScope,
              },
            });
            return;
          }

          const restoredLifecycleState = device.lastHeartbeatAt ? 'ACTIVE' : 'TRUSTED';
          updatedDevice = await repo.updateDeviceState({
            deviceId: device.id,
            lifecycleState: restoredLifecycleState,
          });

          payloadSummary = {
            lostMode: false,
            executionScope: 'SERVER_ACCOUNT_STATE',
          };
          commandStatus = CommandStatus.COMPLETED;
          statusMessage = `Server-side Lost Mode cleared for ${device.name}.`;
          auditEventType = 'DEVICE_ACTION_LOST_MODE_DISABLED';

          notificationData = {
            type: 'LOST_MODE_DISABLED',
            severity: 'PROTECTED',
            category: 'Devices',
            title: `Lost Mode cleared for ${device.name}`,
            message: statusMessage,
          };
        } else if (actionType === 'REQUEST_DEVICE_STATUS') {
          const locationSnapshot = buildDeviceLocationSummary(device, now, latestHeartbeat);
          payloadSummary = {
            locationSnapshot,
          };
          commandStatus = CommandStatus.QUEUED;
          statusMessage = `Status check queued for ${device.name}. Awaiting signed device heartbeat/receipt.`;
          auditEventType = 'DEVICE_ACTION_STATUS_CHECKED';

          notificationData = {
            type: 'SECURITY_CHECK',
            severity: 'INFO',
            category: 'Security',
            title: `Security check queued for ${device.name}`,
            message: statusMessage,
          };
        }

        if (
          requiredScope &&
          actionType !== 'ENABLE_LOST_MODE' &&
          actionType !== 'DISABLE_LOST_MODE'
        ) {
          const consumedActionStepUp = await repo.consumeStepUp({
            sessionId: ctx.session.id,
            acceptableScopes: acceptableStepUpScopes(requiredScope as StepUpScope),
            now,
          });
          if (!consumedActionStepUp) {
            res.status(403).json({
              error: {
                code: 'STEP_UP_REQUIRED',
                message:
                  'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
                requiredScope,
              },
            });
            return;
          }
        }

        const commandRecord = await repo.createRemoteCommand({
          deviceId: device.id,
          issuerUserId: ctx.user.id,
          actionType,
          status: commandStatus,
          statusMessage,
          payloadSummary,
          requestedAt: now,
          completedAt: commandStatus === CommandStatus.COMPLETED ? now : null,
        });

        const auditEntry = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: auditEventType,
          metadata: {
            deviceId: device.id,
            deviceName: device.name,
            actionType,
            status: commandStatus,
            statusMessage,
            ...(typeof payloadSummary.title === 'string'
              ? { messageTitle: payloadSummary.title }
              : {}),
            ...(payloadSummary.locationSnapshot
              ? {
                  regionSummary: (
                    payloadSummary.locationSnapshot as DeviceLocationSummaryDto
                  ).regionSummary,
                }
              : {}),
          },
        });

        let createdNotification: NotificationItemDto | null = null;
        if (notificationData) {
          const notif = await repo.createNotification({
            userId: ctx.user.id,
            type: notificationData.type,
            severity: notificationData.severity,
            category: notificationData.category,
            title: notificationData.title,
            message: notificationData.message,
            relatedDeviceId: device.id,
            relatedDeviceName: device.name,
            relatedEventId: auditEntry.id,
            actionLabel: 'View device',
            actionTarget: `device:${device.id}`,
            metadata: {
              actionType,
              commandId: commandRecord.id,
            },
          });
          createdNotification = toNotificationDto(notif);
        }

        // One-time consumption: clear step-up after a successful sensitive action
        if (requiredScope) {
          await repo.clearStepUp(ctx.session.id);
        }

        const credentials = await repo.listCredentialsByDeviceId(device.id);
        res.status(200).json({
          action: toDeviceActionDto(commandRecord, device.name),
          device: toSafeDeviceDto(updatedDevice, credentials),
          notification: createdNotification,
          locationSummary: buildDeviceLocationSummary(updatedDevice, now, latestHeartbeat),
        });
      } catch {
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to process device action.',
          },
        });
      }
    }
  );

  // ============================================================================
  // Prompt 0008 — Security Event Engine, Risk Assessment, Stateful Commands & Heartbeat Routes
  // ============================================================================

  /**
   * GET /api/events
   * Lists SecurityEvents for the authenticated user with optional filtering.
   */
  router.get(
    '/events',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const category =
          typeof req.query.category === 'string' && req.query.category !== 'All'
            ? req.query.category.trim()
            : undefined;
        const deviceId =
          typeof req.query.deviceId === 'string' && req.query.deviceId.trim().length > 0
            ? req.query.deviceId.trim()
            : undefined;
        const severity =
          typeof req.query.severity === 'string' && req.query.severity.trim().length > 0
            ? req.query.severity.trim().toUpperCase()
            : undefined;
        const type =
          typeof req.query.type === 'string' && req.query.type.trim().length > 0
            ? req.query.type.trim().toUpperCase()
            : undefined;

        const [events, userDevices] = await Promise.all([
          repo.listSecurityEventsByUserId(ctx.user.id, {
            category,
            deviceId,
            severity,
            limit: 80,
          }),
          repo.listDevicesByUserId(ctx.user.id, { includeDecommissioned: true }),
        ]);

        const filteredEvents = type ? events.filter((e) => e.type === type) : events;

        const deviceLookup = new Map<string, string>();
        for (const { device } of userDevices) {
          deviceLookup.set(device.id, device.name);
        }

        res.status(200).json({
          events: filteredEvents.map((e) =>
            eventEngine.toDto(e, e.deviceId ? deviceLookup.get(e.deviceId) ?? null : null)
          ),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load security events.' },
        });
      }
    }
  );

  /**
   * POST /api/events
   * Validates and ingests a SecurityEvent for the authenticated user.
   * Never trusts client-supplied userId; enforces strict device ownership, clock-skew, and metadata safety.
   */
  router.post(
    '/events',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const result = await eventEngine.ingestEvent({
          userId: ctx.user.id,
          deviceId: typeof req.body?.deviceId === 'string' ? req.body.deviceId.trim() : null,
          category: req.body?.category,
          type: req.body?.type,
          severity: req.body?.severity,
          occurredAt: req.body?.occurredAt,
          title: typeof req.body?.title === 'string' ? sanitizePlainText(req.body.title, 180) : undefined,
          description:
            typeof req.body?.description === 'string'
              ? sanitizePlainText(req.body.description, 600)
              : undefined,
          metadata: req.body?.metadata,
          source: req.body?.source ?? 'WEB',
          correlationId:
            typeof req.body?.correlationId === 'string' ? req.body.correlationId.trim() : null,
        });

        res.status(201).json({
          event: result.event,
          notification: result.notificationCreated
            ? toNotificationDto(result.notificationCreated)
            : null,
          riskAssessment: result.riskAssessment,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Invalid security event.';
        if (message.startsWith('CROSS_USER_DEVICE_REFERENCE')) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }
        res.status(400).json({
          error: {
            code: 'INVALID_SECURITY_EVENT',
            message,
          },
        });
      }
    }
  );

  /**
   * GET /api/security/risk
   * Evaluates and returns the deterministic RiskAssessmentDto (0-100 score, status, factors, recommendations).
   */
  router.get(
    '/security/risk',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId =
          typeof req.query.deviceId === 'string' && req.query.deviceId.trim().length > 0
            ? req.query.deviceId.trim()
            : null;

        if (deviceId) {
          const device = await repo.findDeviceById(deviceId);
          if (!device || device.userId !== ctx.user.id) {
            res.status(404).json({
              error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
            });
            return;
          }
        }

        const riskAssessment = await eventEngine.evaluateUserRisk(ctx.user.id, deviceId);
        res.status(200).json({
          riskAssessment,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to evaluate security risk.' },
        });
      }
    }
  );

  /**
   * POST /api/demo/events
   * Triggers a clearly labeled Demo Security Event simulation (Prompt 0008 Part 13).
   */
  router.post(
    '/demo/events',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      // Demo simulations must never run in production or stand in for real device evidence.
      if (
        process.env.NODE_ENV === 'production' ||
        process.env.APP_ENV === 'production' ||
        process.env.VAJRA_ENABLE_DEMO_ENDPOINTS === 'false'
      ) {
        res.status(404).json({
          error: {
            code: 'DEMO_DISABLED',
            message: 'Demo event endpoints are disabled in this environment.',
          },
        });
        return;
      }
      try {
        const ctx = req.authContext!;
        const scenario = String(req.body?.scenario ?? '').trim() as DemoEventScenario;
        if (!DEMO_EVENT_SCENARIOS.includes(scenario)) {
          res.status(400).json({
            error: {
              code: 'INVALID_DEMO_SCENARIO',
              message: 'Unsupported demo security event scenario.',
            },
          });
          return;
        }

        const deviceId =
          typeof req.body?.deviceId === 'string' && req.body.deviceId.trim().length > 0
            ? req.body.deviceId.trim()
            : null;

        if (deviceId) {
          const device = await repo.findDeviceById(deviceId);
          if (!device || device.userId !== ctx.user.id) {
            res.status(404).json({
              error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
            });
            return;
          }
        }

        const result = await eventEngine.triggerDemoScenario(ctx.user.id, scenario, deviceId);
        res.status(201).json({
          event: result.event,
          notification: result.notificationCreated
            ? toNotificationDto(result.notificationCreated)
            : null,
          riskAssessment: result.riskAssessment,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to trigger demo security event.' },
        });
      }
    }
  );

  /**
   * GET /api/devices/:id/commands
   * Lists stateful commands for a user's device, including expired command cleanup and CommandResult records.
   */
  router.get(
    '/devices/:id/commands',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        await repo.expireStaleRemoteCommands({ deviceId: device.id, now: new Date() });
        const commands = await repo.listRemoteCommandsByDeviceId(device.id, ctx.user.id, 30);
        const dtos = await Promise.all(
          commands.map(async (cmd) => {
            const result = await repo.findCommandResultByCommandId(cmd.id);
            return toDeviceActionDto(cmd, device.name, result);
          })
        );
        const latestHeartbeat = await repo.getLatestDeviceHeartbeat(device.id);

        res.status(200).json({
          commands: dtos,
          latestHeartbeat: latestHeartbeat ? toDeviceHeartbeatDto(latestHeartbeat) : null,
          locationSummary: buildDeviceLocationSummary(device, new Date(), latestHeartbeat),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load device commands.' },
        });
      }
    }
  );

  /**
   * GET /api/devices/:id/battery-history
   * Returns a 24-hour battery level trend sequence for an owned Android device.
   * Strictly reads genuinely persisted heartbeat readings without synthetic fabrication.
   */
  router.get(
    '/devices/:id/battery-history',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        if (!deviceId || deviceId.length > 64) {
          res.status(400).json({
            error: { code: 'INVALID_DEVICE_ID', message: 'Invalid device identifier.' },
          });
          return;
        }

        const device = await repo.findDeviceById(deviceId);
        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        if (device.deviceType !== 'ANDROID') {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_PLATFORM',
              message: 'Battery trend telemetry is only supported for Android devices.',
            },
          });
          return;
        }

        const now = new Date();
        const since = new Date(now.getTime() - 24 * 3600 * 1000);
        const heartbeats = await repo.listDeviceHeartbeats(device.id, {
          since,
          limit: BATTERY_HISTORY_RESULT_LIMIT,
        });
        const latestHeartbeat = await repo.getLatestDeviceHeartbeat(device.id);

        const readings = mapHeartbeatsToBatteryReadings(heartbeats);

        res.status(200).json({
          deviceId: device.id,
          deviceName: device.name,
          platform: device.deviceType,
          currentLevel:
            typeof latestHeartbeat?.batteryLevel === 'number'
              ? latestHeartbeat.batteryLevel
              : null,
          charging:
            typeof latestHeartbeat?.charging === 'boolean'
              ? latestHeartbeat.charging
              : null,
          readings,
          hasTelemetry: readings.length > 0,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to load battery trend history.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/commands
   * Creates a stateful RemoteCommand (QUEUED by default for agent delivery, or immediate if immediate=true).
   */
  router.post(
    '/devices/:id/commands',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        const rawAction = String(req.body?.actionType ?? '').trim().toUpperCase();
        if (!ALLOWLISTED_DEVICE_ACTIONS.includes(rawAction as AllowlistedDeviceActionType)) {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_DEVICE_ACTION',
              message:
                'This command is not permitted. Only allowlisted protection and recovery commands are supported.',
            },
          });
          return;
        }

        if (
          device.lifecycleState === 'REVOKED' ||
          device.lifecycleState === 'DECOMMISSIONED' ||
          device.lifecycleState === 'ENROLLMENT_PENDING' ||
          device.lifecycleState === 'COMPROMISED'
        ) {
          res.status(409).json({
            error: {
              code: 'DEVICE_NOT_READY_FOR_COMMANDS',
              message:
                device.lifecycleState === 'COMPROMISED'
                  ? 'Device is marked compromised and quarantined from remote commands.'
                  : 'Device must be active and approved before commands can be issued.',
            },
          });
          return;
        }

        const actionType = rawAction as AllowlistedDeviceActionType;

        const commandCapabilityCheck = validateActionCapabilityForDevice(
          actionType,
          device.deviceType,
          'commands'
        );
        if (!commandCapabilityCheck.supported) {
          res.status(400).json({
            error: {
              code: 'UNSUPPORTED_COMMAND_FOR_PLATFORM',
              message: commandCapabilityCheck.reason,
            },
          });
          return;
        }

        const sensitiveCommandScopes: Record<string, string> = {
          ENABLE_LOST_MODE: STEP_UP_SCOPES.ENABLE_LOST_MODE,
          DISABLE_LOST_MODE: STEP_UP_SCOPES.DISABLE_LOST_MODE,
          RING_DEVICE: STEP_UP_SCOPES.SENSITIVE_COMMAND,
          REQUEST_LOCATION: STEP_UP_SCOPES.SENSITIVE_COMMAND,
          DISPLAY_RECOVERY_MESSAGE: STEP_UP_SCOPES.SENSITIVE_COMMAND,
        };
        const cmdRequiredScope = sensitiveCommandScopes[actionType];
        if (cmdRequiredScope && !sessionHasValidStepUp(ctx.session, cmdRequiredScope as any)) {
          res.status(403).json({
            error: {
              code: 'STEP_UP_REQUIRED',
              message:
                'This command requires fresh multi-factor verification. Please complete MFA step-up and retry.',
              requiredScope: cmdRequiredScope,
            },
          });
          return;
        }

        const now = new Date();
        const ttlMinutes =
          typeof req.body?.ttlMinutes === 'number'
            ? Math.max(1, Math.min(1440, req.body.ttlMinutes))
            : 60;
        const expiresAt =
          req.body?.expiresAt && !Number.isNaN(new Date(req.body.expiresAt).getTime())
            ? new Date(req.body.expiresAt)
            : new Date(now.getTime() + ttlMinutes * 60 * 1000);

        const payloadSummary: Record<string, unknown> = {};
        if (actionType === 'DISPLAY_RECOVERY_MESSAGE' || actionType === 'ENABLE_LOST_MODE') {
          payloadSummary.title = sanitizePlainText(
            req.body?.title ?? 'Protected Device — Please Return',
            80
          );
          payloadSummary.message = sanitizePlainText(
            req.body?.message ??
              'This device is protected by VAJRA. Please contact the owner to return it.',
            240
          );
          if (req.body?.contactInstruction) {
            payloadSummary.contactInstruction = sanitizePlainText(
              req.body.contactInstruction,
              120
            );
          }
        }

        if (cmdRequiredScope) {
          const consumedCmdStepUp = await repo.consumeStepUp({
            sessionId: ctx.session.id,
            acceptableScopes: acceptableStepUpScopes(cmdRequiredScope as StepUpScope),
            now,
          });
          if (!consumedCmdStepUp) {
            res.status(403).json({
              error: {
                code: 'STEP_UP_REQUIRED',
                message:
                  'This command requires fresh multi-factor verification. Please complete MFA step-up and retry.',
                requiredScope: cmdRequiredScope,
              },
            });
            return;
          }
        }

        const commandRecord = await repo.createRemoteCommand({
          deviceId: device.id,
          issuerUserId: ctx.user.id,
          actionType,
          status: CommandStatus.QUEUED,
          statusMessage: `Queued for ${device.name}. Waiting for device agent delivery.`,
          payloadSummary,
          requestedAt: now,
          expiresAt,
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          deviceId: device.id,
          category: 'Command',
          type: 'COMMAND_CREATED',
          severity: 'INFO',
          source: 'WEB',
          title: `Protection command queued for ${device.name}`,
          description: `Authorized ${actionType.replace(/_/g, ' ').toLowerCase()} command queued for ${device.name}.`,
          metadata: {
            commandId: commandRecord.id,
            actionType,
            status: CommandStatus.QUEUED,
          },
        });

        if (cmdRequiredScope) {
          await repo.clearStepUp(ctx.session.id);
        }

        res.status(201).json({
          command: toDeviceActionDto(commandRecord, device.name, null),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to create device command.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/commands/:commandId/cancel
   * Allows the authenticated owner to cancel a QUEUED or DELIVERED command.
   */
  router.post(
    '/devices/:id/commands/:commandId/cancel',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const commandId = String(req.params.commandId ?? '').trim();

        const device = await repo.findDeviceById(deviceId);
        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        const command = await repo.findRemoteCommandById(commandId);
        if (!command || command.deviceId !== device.id || command.issuerUserId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'COMMAND_NOT_FOUND', message: 'Command not found.' },
          });
          return;
        }

        const now = new Date();
        await repo.expireStaleRemoteCommands({ deviceId: device.id, now });
        const currentCommand = await repo.findRemoteCommandById(commandId);
        if (
          !currentCommand ||
          currentCommand.deviceId !== device.id ||
          currentCommand.issuerUserId !== ctx.user.id
        ) {
          res.status(404).json({
            error: { code: 'COMMAND_NOT_FOUND', message: 'Command not found.' },
          });
          return;
        }

        if (
          currentCommand.status === CommandStatus.CANCELLED ||
          !isLegalCommandTransition(currentCommand.status, CommandStatus.CANCELLED)
        ) {
          res.status(409).json({
            error: {
              code: 'COMMAND_NOT_CANCELLABLE',
              message: `Command in state ${currentCommand.status} can no longer be cancelled.`,
            },
          });
          return;
        }

        const updated = await repo.updateRemoteCommandState({
          commandId: currentCommand.id,
          status: CommandStatus.CANCELLED,
          statusMessage: 'Command cancelled by account owner.',
          completedAt: now,
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          deviceId: device.id,
          category: 'Command',
          type: 'COMMAND_CANCELLED',
          severity: 'INFO',
          source: 'WEB',
          metadata: {
            commandId: currentCommand.id,
            actionType: currentCommand.actionType,
          },
        });

        res.status(200).json({
          command: toDeviceActionDto(updated!, device.name, null),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to cancel command.' },
        });
      }
    }
  );

  // ============================================================================
  // Agent-Authenticated Endpoints (Cryptographic Device Signature Required)
  // ============================================================================

  /**
   * GET /api/devices/:id/commands/pending
   * Agent-authenticated endpoint for a trusted device to fetch its pending/queued commands.
   * Automatically transitions QUEUED commands to DELIVERED.
   */
  router.get(
    '/devices/:id/commands/pending',
    requireTrustedDevice(repo),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!assertDeviceRouteBinding(req, res)) return;
        const device = req.deviceAuthContext!.device;
        const now = new Date();
        await repo.expireStaleRemoteCommands({ deviceId: device.id, now });

        const pending = await repo.listPendingCommandsForDevice(device.id);
        const deliveredCommands: DeviceActionRecordDto[] = [];

        for (const cmd of pending) {
          if (cmd.status === CommandStatus.QUEUED || cmd.status === CommandStatus.PENDING) {
            const updated = await repo.updateRemoteCommandState({
              commandId: cmd.id,
              status: CommandStatus.DELIVERED,
              statusMessage: `Delivered to ${device.name}. Waiting for execution acknowledgment.`,
              deliveredAt: now,
            });
            await eventEngine.ingestEvent({
              userId: device.userId,
              deviceId: device.id,
              category: 'Command',
              type: 'COMMAND_DELIVERED',
              severity: 'INFO',
              source: device.deviceType === 'ANDROID' ? 'ANDROID_AGENT' : 'WINDOWS_AGENT',
              metadata: {
                commandId: cmd.id,
                actionType: cmd.actionType,
              },
              skipNotificationPolicy: true,
            });
            deliveredCommands.push(toDeviceActionDto(updated ?? cmd, device.name, null));
          } else {
            deliveredCommands.push(toDeviceActionDto(cmd, device.name, null));
          }
        }

        res.status(200).json({
          commands: deliveredCommands,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch pending commands.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/commands/:commandId/acknowledge
   * Agent-authenticated endpoint for a trusted device to acknowledge a command before completing it.
   */
  router.post(
    '/devices/:id/commands/:commandId/acknowledge',
    requireTrustedDevice(repo),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!assertDeviceRouteBinding(req, res)) return;
        const device = req.deviceAuthContext!.device;
        const commandId = String(req.params.commandId ?? '').trim();
        const command = await repo.findRemoteCommandById(commandId);

        if (!command || command.deviceId !== device.id) {
          res.status(404).json({
            error: { code: 'COMMAND_NOT_FOUND', message: 'Command not found for this device.' },
          });
          return;
        }

        const now = new Date();
        if (command.expiresAt && command.expiresAt.getTime() <= now.getTime()) {
          await repo.updateRemoteCommandState({
            commandId: command.id,
            status: CommandStatus.EXPIRED,
            statusMessage: 'Command expired before device acknowledgment.',
          });
          res.status(409).json({
            error: { code: 'COMMAND_EXPIRED', message: 'Command has expired.' },
          });
          return;
        }

        if (
          command.status !== CommandStatus.QUEUED &&
          command.status !== CommandStatus.PENDING &&
          command.status !== CommandStatus.DELIVERED
        ) {
          res.status(409).json({
            error: {
              code: 'INVALID_COMMAND_STATE',
              message: `Command in state ${command.status} cannot be acknowledged.`,
            },
          });
          return;
        }

        let updated;
        try {
          updated = await repo.updateRemoteCommandState({
            commandId: command.id,
            status: CommandStatus.ACKNOWLEDGED,
            statusMessage: `${device.name} acknowledged command and began execution.`,
            acknowledgedAt: now,
          });
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : '';
          if (message.startsWith('ILLEGAL_COMMAND_TRANSITION:')) {
            res.status(409).json({
              error: {
                code: 'INVALID_COMMAND_STATE',
                message: `Command in state ${command.status} cannot be acknowledged.`,
              },
            });
            return;
          }
          throw err;
        }

        await eventEngine.ingestEvent({
          userId: device.userId,
          deviceId: device.id,
          category: 'Command',
          type: 'COMMAND_ACKNOWLEDGED',
          severity: 'INFO',
          source: device.deviceType === 'ANDROID' ? 'ANDROID_AGENT' : 'WINDOWS_AGENT',
          metadata: {
            commandId: command.id,
            actionType: command.actionType,
          },
          skipNotificationPolicy: true,
        });

        res.status(200).json({
          command: toDeviceActionDto(updated!, device.name, null),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to acknowledge command.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/commands/:commandId/result
   * Agent-authenticated endpoint for a trusted device to report final COMPLETED or FAILED result.
   * Enforces idempotency so duplicate result submissions return the existing result cleanly.
   */
  router.post(
    '/devices/:id/commands/:commandId/result',
    requireTrustedDevice(repo),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!assertDeviceRouteBinding(req, res)) return;
        const device = req.deviceAuthContext!.device;
        const commandId = String(req.params.commandId ?? '').trim();
        const command = await repo.findRemoteCommandById(commandId);

        if (!command || command.deviceId !== device.id) {
          res.status(404).json({
            error: { code: 'COMMAND_NOT_FOUND', message: 'Command not found for this device.' },
          });
          return;
        }

        // Idempotency check: if a result already exists for this commandId, return it
        const existingResult = await repo.findCommandResultByCommandId(command.id);
        if (existingResult) {
          res.status(200).json({
            idempotentReplay: true,
            command: toDeviceActionDto(command, device.name, existingResult),
            result: toCommandResultDto(existingResult),
          });
          return;
        }

        const now = new Date();
        if (command.expiresAt && command.expiresAt.getTime() <= now.getTime()) {
          await repo.updateRemoteCommandState({
            commandId: command.id,
            status: CommandStatus.EXPIRED,
            statusMessage: 'Command expired before result submission.',
          });
          res.status(409).json({
            error: { code: 'COMMAND_EXPIRED', message: 'Command has expired.' },
          });
          return;
        }

        const rawStatus = String(req.body?.status ?? 'COMPLETED').trim().toUpperCase();
        if (rawStatus !== 'COMPLETED' && rawStatus !== 'FAILED') {
          res.status(400).json({
            error: {
              code: 'INVALID_RESULT_STATUS',
              message: 'Result status must be COMPLETED or FAILED.',
            },
          });
          return;
        }

        const safeMessage = sanitizePlainText(
          req.body?.safeMessage ??
            (rawStatus === 'COMPLETED'
              ? `${device.name} completed the protection action.`
              : `${device.name} could not complete the protection action.`),
          240
        );
        const errorCode =
          typeof req.body?.errorCode === 'string'
            ? sanitizePlainText(req.body.errorCode, 64)
            : null;
        const deviceTimestamp =
          req.body?.deviceTimestamp && !Number.isNaN(new Date(req.body.deviceTimestamp).getTime())
            ? new Date(req.body.deviceTimestamp)
            : now;

        const {
          command: updatedCommand,
          result: savedResult,
          idempotentReplay,
        } = await repo.recordCommandExecutionResult({
          commandId: command.id,
          deviceId: device.id,
          status: rawStatus as 'COMPLETED' | 'FAILED',
          receivedAt: now,
          completedAt: now,
          errorCode,
          safeMessage,
          deviceTimestamp,
          resultMetadata:
            req.body?.resultMetadata && typeof req.body.resultMetadata === 'object'
              ? req.body.resultMetadata
              : {},
        });

        if (idempotentReplay) {
          res.status(200).json({
            idempotentReplay: true,
            command: toDeviceActionDto(updatedCommand, device.name, savedResult),
            result: toCommandResultDto(savedResult),
          });
          return;
        }

        await eventEngine.ingestEvent({
          userId: device.userId,
          deviceId: device.id,
          category: 'Command',
          type: rawStatus === 'COMPLETED' ? 'COMMAND_COMPLETED' : 'COMMAND_FAILED',
          severity: rawStatus === 'COMPLETED' ? 'PROTECTED' : 'WARNING',
          source: device.deviceType === 'ANDROID' ? 'ANDROID_AGENT' : 'WINDOWS_AGENT',
          title:
            rawStatus === 'COMPLETED'
              ? `Protection action completed on ${device.name}`
              : `Protection action failed on ${device.name}`,
          description: safeMessage,
          metadata: {
            commandId: command.id,
            actionType: command.actionType,
            status: rawStatus,
            ...(errorCode ? { errorCode } : {}),
          },
        });

        res.status(200).json({
          idempotentReplay: false,
          command: toDeviceActionDto(updatedCommand ?? command, device.name, savedResult),
          result: toCommandResultDto(savedResult),
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : '';
        if (message.startsWith('ILLEGAL_COMMAND_TRANSITION:')) {
          res.status(409).json({
            error: {
              code: 'INVALID_COMMAND_STATE',
              message: 'Command is in a terminal or incompatible state for this receipt.',
            },
          });
          return;
        }
        if (message.startsWith('CONFLICTING_COMMAND_RESULT:')) {
          res.status(409).json({
            error: {
              code: 'CONFLICTING_COMMAND_RESULT',
              message: 'A different final result was already recorded for this command.',
            },
          });
          return;
        }
        if (message === 'COMMAND_DEVICE_MISMATCH') {
          res.status(403).json({
            error: {
              code: 'COMMAND_DEVICE_MISMATCH',
              message: 'Command does not belong to the authenticated device.',
            },
          });
          return;
        }
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to record command result.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/heartbeat
   * Agent-authenticated endpoint for a trusted device to report its health, connectivity, battery,
   * and permissions, while receiving any pending commands.
   */
  router.post(
    '/devices/:id/heartbeat',
    requireTrustedDevice(repo),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!assertDeviceRouteBinding(req, res)) return;
        const device = req.deviceAuthContext!.device;
        const connectivityStatus =
          req.body?.connectivityStatus === 'OFFLINE' ? 'OFFLINE' : 'ONLINE';

        let batteryLevel: number | null = null;
        if (req.body?.batteryLevel !== undefined && req.body?.batteryLevel !== null) {
          const rawBattery = Number(req.body.batteryLevel);
          if (!Number.isFinite(rawBattery) || rawBattery < 0 || rawBattery > 100) {
            res.status(400).json({
              error: {
                code: 'INVALID_BATTERY_LEVEL',
                message: 'Battery level must be an integer between 0 and 100.',
              },
            });
            return;
          }
          batteryLevel = Math.round(rawBattery);
        }

        let charging: boolean | null = null;
        if (req.body?.charging !== undefined && req.body?.charging !== null) {
          if (typeof req.body.charging !== 'boolean') {
            res.status(400).json({
              error: {
                code: 'INVALID_CHARGING_STATE',
                message: 'Charging state must be a boolean.',
              },
            });
            return;
          }
          charging = req.body.charging;
        }

        const rawNet = String(req.body?.networkType ?? 'WIFI').toUpperCase();
        const networkType: 'WIFI' | 'ETHERNET' | 'MOBILE' | 'UNKNOWN' =
          rawNet === 'WIFI' || rawNet === 'ETHERNET' || rawNet === 'MOBILE' ? rawNet : 'UNKNOWN';

        const reportedName = normalizeReportedDeviceName(
          req.body?.deviceName ??
            req.body?.reportedDeviceName ??
            req.body?.hostname ??
            req.body?.machineName
        );

        const heartbeat = await repo.createDeviceHeartbeat({
          deviceId: device.id,
          reportedName,
          connectivityStatus,
          batteryLevel,
          charging,
          networkType,
          osVersion:
            typeof req.body?.osVersion === 'string'
              ? sanitizePlainText(req.body.osVersion, 64)
              : device.osVersion,
          agentVersion:
            typeof req.body?.agentVersion === 'string'
              ? sanitizePlainText(req.body.agentVersion, 32)
              : device.agentVersion,
          permissionSummary:
            typeof req.body?.permissionSummary === 'string'
              ? sanitizePlainText(req.body.permissionSummary, 160)
              : null,
          securitySummary:
            typeof req.body?.securitySummary === 'string'
              ? sanitizePlainText(req.body.securitySummary, 160)
              : null,
          locationPermissionGranted:
            typeof req.body?.locationPermissionGranted === 'boolean'
              ? req.body.locationPermissionGranted
              : null,
        });

        const latestDevice = await repo.findDeviceById(device.id);
        const effectiveDeviceName =
          latestDevice?.name && latestDevice.name.trim().length >= 2
            ? latestDevice.name.trim()
            : getNeutralDeviceFallbackName(device.deviceType);

        if (reportedName && reportedName !== device.name) {
          await repo.appendAuditEvent({
            actorUserId: device.userId,
            actorDeviceId: device.id,
            eventType: 'DEVICE_METADATA_UPDATED',
            metadata: {
              deviceId: device.id,
              previousName: device.name,
              deviceName: effectiveDeviceName,
              source: 'SIGNED_HEARTBEAT',
            },
          });
        }

        const hbEvent = await eventEngine.ingestEvent({
          userId: device.userId,
          deviceId: device.id,
          category: 'Device',
          type: 'DEVICE_HEARTBEAT_RECEIVED',
          severity: 'PROTECTED',
          source: device.deviceType === 'ANDROID' ? 'ANDROID_AGENT' : 'WINDOWS_AGENT',
          title: `Security check completed on ${effectiveDeviceName}`,
          description: `${effectiveDeviceName} checked in over ${networkType.toLowerCase()} with verified identity.`,
          metadata: {
            connectivityStatus,
            ...(batteryLevel !== null ? { batteryLevel } : {}),
            networkType,
          },
          skipNotificationPolicy: true,
        });

        if (latestDevice) {
          const score = hbEvent.riskAssessment.score;
          const mappedRiskLevel =
            score < 40 ? 'CRITICAL' : score < 60 ? 'HIGH' : score < 85 ? 'MEDIUM' : 'LOW';
          await repo.updateDeviceState({
            deviceId: device.id,
            lifecycleState: latestDevice.lifecycleState,
            currentRiskScore: score,
            currentRiskLevel: mappedRiskLevel,
          });
        }

        await repo.expireStaleRemoteCommands({
          deviceId: device.id,
          now: heartbeat.receivedAt,
        });
        const pendingCommands = await repo.listPendingCommandsForDevice(device.id);

        res.status(200).json({
          heartbeat: toDeviceHeartbeatDto(heartbeat),
          pendingCommandCount: pendingCommands.length,
          pendingCommands: pendingCommands.map((c) =>
            toDeviceActionDto(c, effectiveDeviceName, null)
          ),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to record device heartbeat.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/events
   * Plane-2 signed device event ingestion.
   * Requires trusted device credential + signature; binds route :id to authenticated device;
   * reuses SecurityEventEngine for validation, redaction, ownership, and persistence.
   * Never trusts client-supplied risk scores.
   */
  router.post(
    '/devices/:id/events',
    requireTrustedDevice(repo),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!assertDeviceRouteBinding(req, res)) return;
        const device = req.deviceAuthContext!.device;

        // Reject client-supplied risk scores / verification claims
        if (
          req.body?.riskScore !== undefined ||
          req.body?.verified === true ||
          req.body?.clientVerified === true ||
          req.body?.riskLevel !== undefined
        ) {
          res.status(400).json({
            error: {
              code: 'CLIENT_RISK_SCORE_REJECTED',
              message:
                'Client-supplied risk scores or verification flags are not accepted. Risk is computed server-side.',
            },
          });
          return;
        }

        const source =
          device.deviceType === 'ANDROID'
            ? 'ANDROID_AGENT'
            : device.deviceType === 'WINDOWS'
              ? 'WINDOWS_AGENT'
              : 'DEVICE';

        const result = await eventEngine.ingestEvent({
          userId: device.userId,
          deviceId: device.id,
          category: req.body?.category,
          type: req.body?.type,
          severity: req.body?.severity,
          occurredAt: req.body?.occurredAt,
          title:
            typeof req.body?.title === 'string'
              ? sanitizePlainText(req.body.title, 180)
              : undefined,
          description:
            typeof req.body?.description === 'string'
              ? sanitizePlainText(req.body.description, 600)
              : undefined,
          metadata: req.body?.metadata,
          source: typeof req.body?.source === 'string' ? req.body.source : source,
          correlationId:
            typeof req.body?.correlationId === 'string'
              ? req.body.correlationId.trim().slice(0, 128)
              : null,
        });

        res.status(201).json({
          event: result.event,
          notification: result.notificationCreated
            ? toNotificationDto(result.notificationCreated)
            : null,
          riskAssessment: result.riskAssessment,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Invalid security event.';
        if (message.startsWith('CROSS_USER_DEVICE_REFERENCE')) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }
        res.status(400).json({
          error: {
            code: 'INVALID_SECURITY_EVENT',
            message,
          },
        });
      }
    }
  );

  return router;
}
