/**
 * VAJRA — Cryptographic Device Identity & Secure Enrollment Routes
 * Prompt 0004: Cryptographic Device Identity & Secure Enrollment
 *
 * Implements:
 * 1. GET /api/devices — List owned devices (excluding DECOMMISSIONED by default)
 * 2. GET /api/devices/:id — Retrieve single owned device details + active/historical credentials (404 on cross-user access)
 * 3. POST /api/devices/enrollment/initiate — Generate single-use 10-minute enrollment token & QR payload (Plane 1)
 * 4. POST /api/devices/enrollment/submit — Submit asymmetric public key (Ed25519 / ECDSA P-256) + signed Proof-of-Possession
 * 5. POST /api/devices/:id/enrollment/confirm — Confirm device enrollment -> TRUSTED (Plane 1)
 * 6. POST /api/devices/:id/revoke — Permanently revoke device and all credentials -> REVOKED (Plane 1)
 * 7. POST /api/devices/:id/compromised — Flag device as COMPROMISED (Plane 1)
 * 8. POST /api/devices/:id/decommission — Archive a REVOKED device -> DECOMMISSIONED (Plane 1)
 * 9. POST /api/devices/auth/verify — Plane 2 authenticated device request verification endpoint (TRUSTED_DEVICE)
 * 10. POST /api/devices/credentials/rotate — Plane 2 cryptographic key rotation with PoP signature from new key
 */

import { Router, Request, Response } from 'express';
import QRCode from 'qrcode';
import {
  generateEnrollmentChallengeBundle,
  hashEnrollmentToken,
  verifyEnrollmentProof,
  isValidDeviceLifecycleTransition,
  SupportedKeyAlgorithm,
  verifyVerificationPasscode,
  formatVerificationPasscode,
  resolvePasscodeHmacSecret,
} from '../../../packages/security/src/node.ts';
import {
  IdentityRepository,
  DeviceEntity,
  DeviceCredentialEntity,
  DeviceTypeEntity,
} from '../db/repository.ts';
import {
  requireAuthenticatedUser,
  createDeviceAuthenticationMiddleware,
  requireStepUp,
  acceptableStepUpScopes,
  STEP_UP_SCOPES,
} from '../auth/middleware.ts';
import { SlidingWindowRateLimiter } from '../auth/rate-limiter.ts';
import { ownerEventBroadcaster } from '../events/ownerStream.ts';

export interface DeviceRouterOptions {
  repository: IdentityRepository;
  totpEncryptionKey?: string;
}

/**
 * Resolves the authoritative public server URL for QR enrollment payload generation (SEC-02).
 * Strictly validates APP_PUBLIC_ORIGIN in production and rejects host header poisoning.
 */
function resolveCanonicalServerUrl(req: Request): string {
  const isProd =
    process.env.APP_ENV?.toLowerCase() === 'production' ||
    (process.env.NODE_ENV?.toLowerCase() === 'production' && !process.env.APPLET_ID);

  const rawConfigured = process.env.APP_PUBLIC_ORIGIN?.trim() || process.env.APP_URL?.trim();
  if (rawConfigured) {
    try {
      const u = new URL(rawConfigured);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        throw new Error('APP_PUBLIC_ORIGIN protocol must be http: or https:');
      }
      if (u.username || u.password) {
        throw new Error('APP_PUBLIC_ORIGIN must not contain credentials');
      }
      if (u.pathname && u.pathname !== '/') {
        throw new Error('APP_PUBLIC_ORIGIN must be a bare origin without path');
      }
      if (u.search || u.hash) {
        throw new Error('APP_PUBLIC_ORIGIN must not contain query parameters or fragments');
      }
      if (isProd && u.protocol !== 'https:') {
        throw new Error('Production APP_PUBLIC_ORIGIN must enforce https://');
      }
      return `${u.protocol}//${u.host}`;
    } catch (err) {
      if (isProd) {
        throw new Error(`[VAJRA] Invalid APP_PUBLIC_ORIGIN: ${(err as Error).message}`);
      }
    }
  }

  if (isProd) {
    throw new Error(
      '[VAJRA] Fail closed: APP_PUBLIC_ORIGIN must be configured as an explicit https:// origin in production mode.'
    );
  }

  // Development fallback: Strictly permit verified loopback or sandbox host
  const rawHost = (req.get('host') ?? '').trim();
  const isLoopbackHost =
    /^(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$/i.test(rawHost) ||
    Boolean(process.env.APPLET_ID);

  const safeHost = isLoopbackHost ? rawHost : '127.0.0.1:3000';
  const proto = req.protocol === 'https' ? 'https' : 'http';
  return `${proto}://${safeHost}`;
}

export function getNeutralDeviceFallbackName(
  deviceType?: DeviceTypeEntity | string | null
): string {
  const normalized = String(deviceType ?? '')
    .trim()
    .toUpperCase();
  if (normalized === 'WINDOWS') return 'Windows PC';
  if (normalized === 'ANDROID') return 'Android Device';
  return 'Protected Device';
}

export function sanitizeDeviceName(rawName: unknown): {
  valid: boolean;
  sanitizedName?: string;
  error?: string;
} {
  if (typeof rawName !== 'string') {
    return { valid: false, error: 'Device name is required.' };
  }
  const stripped = rawName
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
    .replace(/[<>"'`\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (stripped.length < 2 || stripped.length > 64) {
    return {
      valid: false,
      error: 'Device name must be between 2 and 64 characters.',
    };
  }
  return { valid: true, sanitizedName: stripped };
}

/**
 * Normalizes an agent-reported machine/model label into a safe display name (2..64 chars).
 * Overlong OS hostnames or model strings are safely truncated to 64 characters; missing,
 * blank, or control/punctuation-only values return null so callers fall back cleanly.
 */
export function normalizeReportedDeviceName(rawName: unknown): string | null {
  if (typeof rawName !== 'string') {
    return null;
  }
  const cleaned = rawName
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
    .replace(/[<>"'`\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 64)
    .trim();

  if (cleaned.length < 2) {
    return null;
  }
  return cleaned;
}

export function sanitizeShortMetadata(rawVal: unknown, maxLen = 64): string | null {
  if (typeof rawVal !== 'string' || rawVal.trim().length === 0) {
    return null;
  }
  const cleaned = rawVal
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
    .replace(/[<>"'`\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen);
  return cleaned.length > 0 ? cleaned : null;
}

/**
 * Safe public DTO for DeviceCredential — NEVER exposes enrollmentTokenHash.
 */
export function toSafeDeviceCredentialDto(cred: DeviceCredentialEntity) {
  return {
    id: cred.id,
    deviceId: cred.deviceId,
    keyAlgorithm: cred.keyAlgorithm,
    publicKeyFingerprint: cred.publicKeyFingerprint,
    status: cred.status,
    hardwareBacked: cred.hardwareBacked,
    active: cred.active,
    createdAt: cred.createdAt.toISOString(),
    confirmedAt: cred.confirmedAt ? cred.confirmedAt.toISOString() : null,
    rotatedAt: cred.rotatedAt ? cred.rotatedAt.toISOString() : null,
    revokedAt: cred.revokedAt ? cred.revokedAt.toISOString() : null,
  };
}

/**
 * Safe public DTO for Device + active/pending credential summary.
 */
export function toSafeDeviceDto(
  device: DeviceEntity,
  credentials: DeviceCredentialEntity[] = []
) {
  const activeCred =
    credentials.find((c) => c.active && c.status === 'ACTIVE') ??
    credentials.find((c) => c.status === 'PENDING_CONFIRMATION') ??
    credentials[0] ??
    null;

  const normalizedDisplayName =
    typeof device.name === 'string' && device.name.trim().length >= 2
      ? device.name.trim()
      : getNeutralDeviceFallbackName(device.deviceType);

  return {
    id: device.id,
    userId: device.userId,
    name: normalizedDisplayName,
    deviceType: device.deviceType,
    lifecycleState: device.lifecycleState,
    connectivityStatus: device.connectivityStatus,
    osVersion: device.osVersion,
    agentVersion: device.agentVersion,
    currentRiskScore: device.currentRiskScore,
    currentRiskLevel: device.currentRiskLevel,
    publicKeyFingerprint: activeCred ? activeCred.publicKeyFingerprint : null,
    keyAlgorithm: activeCred ? activeCred.keyAlgorithm : null,
    credentialStatus: activeCred ? activeCred.status : null,
    hardwareBacked: activeCred ? activeCred.hardwareBacked : false,
    lastHeartbeatAt: device.lastHeartbeatAt ? device.lastHeartbeatAt.toISOString() : null,
    lastSeenAt: device.lastSeenAt ? device.lastSeenAt.toISOString() : null,
    enrolledAt: device.enrolledAt ? device.enrolledAt.toISOString() : null,
    revokedAt: device.revokedAt ? device.revokedAt.toISOString() : null,
    compromisedAt: device.compromisedAt ? device.compromisedAt.toISOString() : null,
    createdAt: device.createdAt.toISOString(),
    updatedAt: device.updatedAt.toISOString(),
    credentials: credentials.map(toSafeDeviceCredentialDto),
  };
}

export function requireTrustedDevice(repo: IdentityRepository) {
  return createDeviceAuthenticationMiddleware(repo);
}

/**
 * Ensures the authenticated device (from Plane-2 signature headers) matches
 * the device ID in the route path. Prevents a valid device from acting on
 * another device's path even if it somehow learns the UUID.
 * Returns true if bound; sends 403 and returns false otherwise.
 */
export function assertDeviceRouteBinding(req: Request, res: Response): boolean {
  const authDevice = req.deviceAuthContext?.device;
  const routeDeviceId = String(req.params.id ?? '').trim();
  if (!authDevice || !routeDeviceId || authDevice.id !== routeDeviceId) {
    res.status(403).json({
      error: {
        code: 'DEVICE_ROUTE_MISMATCH',
        message:
          'Authenticated device identity does not match the device ID in the request path.',
      },
    });
    return false;
  }
  return true;
}

export function createDeviceRouter(options: DeviceRouterOptions): Router {
  const router = Router();
  const repo = options.repository;
  const requireTrustedDevice = createDeviceAuthenticationMiddleware(repo);

  const enrollmentSubmitLimiter = new SlidingWindowRateLimiter({
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000,
  });

  /**
   * GET /api/devices
   * Lists all devices owned by the authenticated user.
   */
  router.get(
    '/devices',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const includeDecommissioned = req.query.includeDecommissioned === 'true';
        const items = await repo.listDevicesByUserId(ctx.user.id, {
          includeDecommissioned,
        });

        res.status(200).json({
          devices: items.map(({ device, credentials }) => toSafeDeviceDto(device, credentials)),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to list devices.' },
        });
      }
    }
  );

  /**
   * GET /api/devices/pending-approvals
   * Retrieves all devices owned by the authenticated user awaiting owner authorization.
   */
  router.get(
    '/devices/pending-approvals',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const pendingItems = await repo.listPendingApprovalDevices(ctx.user.id);
        res.status(200).json({
          pendingApprovals: pendingItems.map(({ device, credential }) => ({
            deviceId: device.id,
            name:
              typeof device.name === 'string' && device.name.trim().length >= 2
                ? device.name.trim()
                : getNeutralDeviceFallbackName(device.deviceType),
            deviceType: device.deviceType,
            lifecycleState: device.lifecycleState,
            publicKeyFingerprint: credential.publicKeyFingerprint,
            keyAlgorithm: credential.keyAlgorithm,
            hardwareBacked: false,
            osVersion: device.osVersion,
            agentVersion: device.agentVersion,
            createdAt: device.createdAt.toISOString(),
            submittedAt: credential.createdAt.toISOString(),
          })),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve pending approvals.' },
        });
      }
    }
  );

  /**
   * GET /api/events/stream
   * Authenticated SSE stream for owner real-time notifications.
   * Dispatches DEVICE_AWAITING_APPROVAL, DEVICE_CONNECTED, and DEVICE_REJECTED.
   */
  router.get(
    '/events/stream',
    requireAuthenticatedUser,
    (req: Request, res: Response): void => {
      const user = req.authContext?.user;
      if (!user) {
        res.status(401).json({
          error: { code: 'UNAUTHENTICATED', message: 'Authentication required.' },
        });
        return;
      }

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders?.();

      const cleanup = ownerEventBroadcaster.registerClient(user.id, res);

      req.on('close', () => {
        cleanup();
      });
    }
  );

  /**
   * GET /api/devices/:id
   * Retrieves a single owned device and its credential history.
   * Returns 404 Not Found if the device does not exist OR belongs to another user (anti-enumeration).
   */
  router.get(
    '/devices/:id',
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

        const credentials = await repo.listCredentialsByDeviceId(device.id);
        res.status(200).json({
          device: toSafeDeviceDto(device, credentials),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve device.' },
        });
      }
    }
  );

  /**
   * PATCH /api/devices/:id (also aliased at POST /api/devices/:id/rename)
   * Updates the display name of an owned device without modifying its cryptographic identity,
   * publicKeyFingerprint, or userId ownership binding.
   */
  const handleRenameDevice = async (req: Request, res: Response): Promise<void> => {
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

      if (device.lifecycleState === 'DECOMMISSIONED') {
        res.status(409).json({
          error: {
            code: 'INVALID_LIFECYCLE_TRANSITION',
            message: 'Cannot rename an archived device.',
          },
        });
        return;
      }

      const rawName = req.body?.name ?? req.body?.deviceName ?? req.body?.proposedDeviceName;
      const nameCheck = sanitizeDeviceName(rawName);
      if (!nameCheck.valid || !nameCheck.sanitizedName) {
        res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: nameCheck.error ?? 'Invalid device name.',
          },
        });
        return;
      }

      const previousName = device.name;
      const updatedDevice = await repo.updateDeviceState({
        deviceId: device.id,
        lifecycleState: device.lifecycleState,
        name: nameCheck.sanitizedName,
      });

      await repo.appendAuditEvent({
        actorUserId: ctx.user.id,
        actorDeviceId: device.id,
        eventType: 'DEVICE_METADATA_UPDATED',
        metadata: {
          deviceId: device.id,
          previousName,
          deviceName: updatedDevice.name,
          source: 'OWNER_RENAME',
        },
      });

      const credentials = await repo.listCredentialsByDeviceId(device.id);
      res.status(200).json({
        device: toSafeDeviceDto(updatedDevice, credentials),
      });
    } catch {
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to update device name.' },
      });
    }
  };

  router.patch('/devices/:id', requireAuthenticatedUser, handleRenameDevice);
  router.post('/devices/:id/rename', requireAuthenticatedUser, handleRenameDevice);

  /**
   * POST /api/devices/enrollment/initiate
   * Also aliased at POST /api/devices/enrollment when action === 'INITIATE'.
   * Creates an ENROLLMENT_PENDING device record and a 10-minute single-use EnrollmentChallenge.
   * Raw enrollment token is returned ONLY once in this response; only SHA-256 hash is stored in DB.
   */
  const handleInitiateEnrollment = async (req: Request, res: Response): Promise<void> => {
    try {
      const ctx = req.authContext!;
      const rawType = String(
        req.body?.expectedDeviceType ?? req.body?.deviceType ?? ''
      )
        .trim()
        .toUpperCase();
      if (rawType !== 'WINDOWS' && rawType !== 'ANDROID') {
        res.status(400).json({
          error: {
            code: 'INVALID_DEVICE_TYPE',
            message: 'Device type must be WINDOWS or ANDROID.',
          },
        });
        return;
      }

      const deviceType = rawType as DeviceTypeEntity;
      const rawName = req.body?.proposedDeviceName ?? req.body?.deviceName ?? req.body?.name;

      let resolvedInitialName: string;
      if (
        rawName === undefined ||
        rawName === null ||
        (typeof rawName === 'string' && rawName.trim().length === 0)
      ) {
        resolvedInitialName = getNeutralDeviceFallbackName(deviceType);
      } else {
        const nameCheck = sanitizeDeviceName(rawName);
        if (!nameCheck.valid || !nameCheck.sanitizedName) {
          res.status(400).json({
            error: {
              code: 'INVALID_INPUT',
              message: nameCheck.error ?? 'Invalid device name.',
            },
          });
          return;
        }
        resolvedInitialName = nameCheck.sanitizedName;
      }

      const hmacSecret = resolvePasscodeHmacSecret();
      const bundle = generateEnrollmentChallengeBundle(new Date(), hmacSecret);

      const { device, challenge } = await repo.createEnrollmentPendingDevice({
        userId: ctx.user.id,
        name: resolvedInitialName,
        deviceType,
        tokenHash: bundle.tokenHash,
        nonce: bundle.challengeNonce,
        passcodeHash: bundle.passcodeHash,
        expiresAt: bundle.expiresAt,
      });

      const serverUrl = resolveCanonicalServerUrl(req);

      const qrPayload = JSON.stringify({
        protocol: 'VAJRA_ENROLL_V1',
        serverUrl,
        deviceId: device.id,
        deviceType: device.deviceType,
        enrollmentToken: bundle.rawEnrollmentToken,
        challengeNonce: challenge.nonce,
        expiresAt: challenge.expiresAt.toISOString(),
      });

      const qrCodeDataUrl = await QRCode.toDataURL(qrPayload, {
        errorCorrectionLevel: 'M',
        margin: 2,
        width: 240,
      });

      await repo.appendAuditEvent({
        actorUserId: ctx.user.id,
        actorDeviceId: device.id,
        eventType: 'DEVICE_ENROLLMENT_INITIATED',
        metadata: {
          deviceId: device.id,
          deviceName: device.name,
          deviceType: device.deviceType,
          expiresAt: challenge.expiresAt.toISOString(),
        },
      });

      res.status(201).json({
        device: toSafeDeviceDto(device, []),
        enrollment: {
          deviceId: device.id,
          lifecycleState: device.lifecycleState,
          serverUrl,
          enrollmentToken: bundle.rawEnrollmentToken,
          challengeNonce: challenge.nonce,
          verificationPasscode: bundle.verificationPasscode,
          formattedPasscode: formatVerificationPasscode(bundle.verificationPasscode),
          expiresAt: challenge.expiresAt.toISOString(),
          qrCodeDataUrl,
        },
      });
    } catch {
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to initiate device enrollment.',
        },
      });
    }
  };

  router.post(
    '/devices/enrollment/initiate',
    requireAuthenticatedUser,
    handleInitiateEnrollment
  );

  router.post(
    '/devices/enrollment',
    requireAuthenticatedUser,
    handleInitiateEnrollment
  );

  /**
   * GET /api/devices/:id/enrollment/status
   * Polling endpoint for web application and companion agents during onboarding.
   * Tracks: PENDING_SCAN -> AWAITING_OWNER_CONFIRMATION -> CONNECTED
   */
  router.get(
    '/devices/:id/enrollment/status',
    async (req: Request, res: Response): Promise<void> => {
      try {
        const user = req.authContext?.user;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        if (!device) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        if (user && device.userId !== user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        const credentials = await repo.listCredentialsByDeviceId(device.id);
        const pendingCred = credentials.find((c) => c.status === 'PENDING_CONFIRMATION');
        const activeCred = credentials.find((c) => c.status === 'ACTIVE' && c.active);

        let enrollmentStatus: 'PENDING_SCAN' | 'AWAITING_OWNER_CONFIRMATION' | 'CONNECTED' | 'REVOKED';
        if (device.lifecycleState === 'TRUSTED' || activeCred) {
          enrollmentStatus = 'CONNECTED';
        } else if (device.lifecycleState === 'REVOKED' || device.lifecycleState === 'DECOMMISSIONED') {
          enrollmentStatus = 'REVOKED';
        } else if (pendingCred) {
          enrollmentStatus = 'AWAITING_OWNER_CONFIRMATION';
        } else {
          enrollmentStatus = 'PENDING_SCAN';
        }

        res.status(200).json({
          deviceId: device.id,
          deviceName: device.name,
          deviceType: device.deviceType,
          lifecycleState: device.lifecycleState,
          status: enrollmentStatus,
          pendingCredential: user && pendingCred ? toSafeDeviceCredentialDto(pendingCred) : null,
          activeCredential: user && activeCred ? toSafeDeviceCredentialDto(activeCred) : null,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve enrollment status.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/enrollment/submit
   * Endpoint agent submits the single-use enrollment token, its asymmetric public key (Ed25519 or ECDSA P-256),
   * and a cryptographic Proof-of-Possession signature over the enrollment transcript.
   */
  router.post(
    '/devices/enrollment/submit',
    async (req: Request, res: Response): Promise<void> => {
      try {
        const rawToken = req.body?.enrollmentToken;
        const publicKeyPem = req.body?.publicKeyPem;
        const signatureBase64 = req.body?.signatureBase64 ?? req.body?.proofSignature;
        const timestampIso = req.body?.timestamp ?? req.body?.timestampIso;
        const clientNonce = req.body?.clientNonce ?? req.body?.nonce;
        const requestedAlgorithm = req.body?.keyAlgorithm as SupportedKeyAlgorithm | undefined;

        if (typeof rawToken !== 'string' || rawToken.trim().length < 8) {
          res.status(400).json({
            error: {
              code: 'INVALID_ENROLLMENT_TOKEN',
              message: 'Valid enrollment token is required.',
            },
          });
          return;
        }

        const tokenHash = hashEnrollmentToken(rawToken);
        const rateKey = `enroll-submit:${tokenHash.slice(0, 24)}`;
        const rateStatus = enrollmentSubmitLimiter.check(rateKey);
        if (!rateStatus.allowed) {
          res.status(429).json({
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Too many enrollment submission attempts.',
            },
          });
          return;
        }

        const challenge = await repo.findEnrollmentChallengeByTokenHash(tokenHash);
        if (!challenge) {
          enrollmentSubmitLimiter.recordAttempt(rateKey);
          res.status(401).json({
            error: {
              code: 'INVALID_ENROLLMENT_TOKEN',
              message: 'Invalid or unrecognized enrollment token.',
            },
          });
          return;
        }

        const now = new Date();
        if (challenge.consumedAt !== null) {
          res.status(409).json({
            error: {
              code: 'ENROLLMENT_TOKEN_ALREADY_USED',
              message: 'This single-use enrollment token has already been consumed.',
            },
          });
          return;
        }

        if (now >= challenge.expiresAt) {
          res.status(410).json({
            error: {
              code: 'ENROLLMENT_TOKEN_EXPIRED',
              message: 'Enrollment token has expired.',
            },
          });
          return;
        }

        const device = await repo.findDeviceById(challenge.deviceId);
        if (!device || device.lifecycleState !== 'ENROLLMENT_PENDING') {
          res.status(409).json({
            error: {
              code: 'INVALID_DEVICE_STATE',
              message: 'Device is not in ENROLLMENT_PENDING state.',
            },
          });
          return;
        }

        if (challenge.passcodeHash) {
          const rawPasscode = req.body?.verificationPasscode ?? req.body?.passcode;
          if (typeof rawPasscode !== 'string' || rawPasscode.trim().length === 0) {
            res.status(400).json({
              error: {
                code: 'PASSCODE_REQUIRED',
                message: 'A 6-digit verification passcode is required for enrollment.',
              },
            });
            return;
          }

          const hmacSecret = resolvePasscodeHmacSecret();
          const passcodeMatches = verifyVerificationPasscode(
            rawPasscode,
            challenge.passcodeHash,
            challenge.nonce,
            hmacSecret
          );

          if (!passcodeMatches) {
            // Atomic conditional check-and-increment: increments ONLY when challenge is unconsumed, unexpired, and failedAttempts < 5
            const attemptResult = await repo.recordFailedEnrollmentChallengeAttemptAtomic(
              challenge.id,
              5,
              now
            );
            // Connect to enrollment rate limiter
            enrollmentSubmitLimiter.recordAttempt(rateKey);

            if (attemptResult.reason === 'ALREADY_CONSUMED') {
              res.status(409).json({
                error: {
                  code: 'ENROLLMENT_TOKEN_ALREADY_USED',
                  message: 'This enrollment challenge has already been consumed.',
                },
              });
              return;
            }

            if (attemptResult.reason === 'EXPIRED') {
              res.status(410).json({
                error: {
                  code: 'ENROLLMENT_TOKEN_EXPIRED',
                  message: 'Enrollment token has expired.',
                },
              });
              return;
            }

            if (attemptResult.locked || attemptResult.failedAttempts >= 5) {
              res.status(429).json({
                error: {
                  code: 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS',
                  message: 'Too many invalid verification passcode attempts. Enrollment challenge locked.',
                },
              });
              return;
            }

            res.status(401).json({
              error: {
                code: 'INVALID_VERIFICATION_PASSCODE',
                message: 'Incorrect verification passcode entered. Please re-enter the code shown on screen.',
              },
            });
            return;
          }

          // Passcode matched: check latest authoritative challenge state to prevent race against concurrent lockouts
          const freshChallenge = await repo.findEnrollmentChallengeByTokenHash(tokenHash);
          if (!freshChallenge) {
            res.status(404).json({
              error: {
                code: 'CHALLENGE_NOT_FOUND',
                message: 'Enrollment challenge not found.',
              },
            });
            return;
          }
          if (freshChallenge.consumedAt !== null) {
            res.status(409).json({
              error: {
                code: 'ENROLLMENT_TOKEN_ALREADY_USED',
                message: 'This enrollment challenge has already been consumed.',
              },
            });
            return;
          }
          if (freshChallenge.expiresAt.getTime() <= now.getTime()) {
            res.status(410).json({
              error: {
                code: 'ENROLLMENT_TOKEN_EXPIRED',
                message: 'Enrollment token has expired.',
              },
            });
            return;
          }
          if ((freshChallenge.failedAttempts ?? 0) >= 5) {
            res.status(429).json({
              error: {
                code: 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS',
                message: 'Too many invalid verification passcode attempts. Enrollment challenge locked.',
              },
            });
            return;
          }
        }

        const proofResult = verifyEnrollmentProof({
          publicKeyPem: typeof publicKeyPem === 'string' ? publicKeyPem : '',
          expectedAlgorithm: requestedAlgorithm,
          signatureBase64: typeof signatureBase64 === 'string' ? signatureBase64 : '',
          deviceId: device.id,
          enrollmentToken: rawToken,
          challengeNonce: challenge.nonce,
          timestampIso: typeof timestampIso === 'string' ? timestampIso : '',
          clientNonce: typeof clientNonce === 'string' ? clientNonce : '',
          nowMs: now.getTime(),
        });

        if (
          !proofResult.valid ||
          !proofResult.keyAlgorithm ||
          !proofResult.publicKeyFingerprint ||
          !proofResult.normalizedPublicKeyPem
        ) {
          enrollmentSubmitLimiter.recordAttempt(rateKey);
          await repo.appendAuditEvent({
            actorUserId: device.userId,
            actorDeviceId: device.id,
            eventType: 'DEVICE_ENROLLMENT_PROOF_FAILURE',
            metadata: {
              deviceId: device.id,
              reason: proofResult.error ?? 'PROOF_VERIFICATION_FAILED',
            },
          });
          res.status(400).json({
            error: {
              code: 'ENROLLMENT_PROOF_INVALID',
              message: proofResult.error ?? 'Enrollment proof-of-possession failed.',
            },
          });
          return;
        }

        // Prevent duplicate public key fingerprints across devices
        const existingFingerprint = await repo.findCredentialByFingerprint(
          proofResult.publicKeyFingerprint
        );
        if (existingFingerprint) {
          res.status(409).json({
            error: {
              code: 'DUPLICATE_PUBLIC_KEY',
              message: 'This public key fingerprint is already registered.',
            },
          });
          return;
        }

        const reportedName = normalizeReportedDeviceName(
          req.body?.deviceName ??
            req.body?.reportedDeviceName ??
            req.body?.hostname ??
            req.body?.machineName
        );
        const osVersion = sanitizeShortMetadata(req.body?.osVersion, 64);
        const agentVersion = sanitizeShortMetadata(req.body?.agentVersion, 32);
        // SEC-05: Server must not trust unverified client-supplied boolean claims for hardware attestation
        // Without cryptographic attestation certificates (Android Key Attestation / TPM EK), stored as false
        const hardwareBacked = false;

        const submitted = await repo.submitDevicePublicKey({
          challengeId: challenge.id,
          deviceId: device.id,
          keyAlgorithm: proofResult.keyAlgorithm,
          publicKeyPem: proofResult.normalizedPublicKeyPem,
          publicKeyFingerprint: proofResult.publicKeyFingerprint,
          hardwareBacked,
          reportedName,
          osVersion,
          agentVersion,
          tokenHash: challenge.tokenHash,
          enrollmentExpiresAt: challenge.expiresAt,
          verifiedAt: now,
        });

        const effectiveDeviceName =
          submitted.device.name && submitted.device.name.trim().length >= 2
            ? submitted.device.name.trim()
            : getNeutralDeviceFallbackName(submitted.device.deviceType);

        const auditKeySubmitted = await repo.appendAuditEvent({
          actorUserId: device.userId,
          actorDeviceId: device.id,
          eventType: 'DEVICE_KEY_SUBMITTED',
          metadata: {
            deviceId: device.id,
            deviceName: effectiveDeviceName,
            keyAlgorithm: submitted.credential.keyAlgorithm,
            publicKeyFingerprint: submitted.credential.publicKeyFingerprint,
            hardwareBacked: submitted.credential.hardwareBacked,
          },
        });

        await repo.createNotification({
          userId: device.userId,
          type: 'DEVICE_CONNECTED',
          severity: 'ATTENTION',
          category: 'Needs Attention',
          title: `Approve ${effectiveDeviceName}`,
          message: `${effectiveDeviceName} connected with a verified identity and is waiting for your confirmation.`,
          relatedDeviceId: device.id,
          relatedDeviceName: effectiveDeviceName,
          relatedEventId: auditKeySubmitted.id,
          actionLabel: 'Review device',
          actionTarget: `device:${device.id}`,
        });

        ownerEventBroadcaster.emitToUser(device.userId, 'DEVICE_AWAITING_APPROVAL', {
          deviceId: device.id,
          deviceName: effectiveDeviceName,
          deviceType: submitted.device.deviceType,
          lifecycleState: submitted.device.lifecycleState,
          publicKeyFingerprint: submitted.credential.publicKeyFingerprint,
          keyAlgorithm: submitted.credential.keyAlgorithm,
          hardwareBacked: false,
          osVersion: submitted.device.osVersion,
          agentVersion: submitted.device.agentVersion,
          timestamp: now.toISOString(),
        });

        res.status(200).json({
          status: 'KEY_SUBMITTED_AWAITING_OWNER_CONFIRMATION',
          device: toSafeDeviceDto(submitted.device, [submitted.credential]),
          credential: toSafeDeviceCredentialDto(submitted.credential),
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err ?? '');
        if (message === 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS') {
          res.status(429).json({
            error: {
              code: 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS',
              message: 'Too many invalid verification passcode attempts. Enrollment challenge locked.',
            },
          });
          return;
        }
        if (message === 'ENROLLMENT_TOKEN_ALREADY_USED') {
          res.status(409).json({
            error: {
              code: 'ENROLLMENT_TOKEN_ALREADY_USED',
              message: 'This enrollment challenge has already been consumed.',
            },
          });
          return;
        }
        if (message === 'ENROLLMENT_TOKEN_EXPIRED') {
          res.status(410).json({
            error: {
              code: 'ENROLLMENT_TOKEN_EXPIRED',
              message: 'Enrollment token has expired.',
            },
          });
          return;
        }
        if (message === 'DUPLICATE_PUBLIC_KEY_FINGERPRINT' || message === 'DUPLICATE_PUBLIC_KEY') {
          res.status(409).json({
            error: {
              code: 'DUPLICATE_PUBLIC_KEY',
              message: 'This public key fingerprint is already registered.',
            },
          });
          return;
        }
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to process device key submission.',
          },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/enrollment/confirm
   * Authenticated user confirms the submitted device public key fingerprint,
   * transitioning the device from ENROLLMENT_PENDING -> TRUSTED and activating its DeviceCredential.
   */
  router.post(
    '/devices/:id/enrollment/confirm',
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

        if (
          !isValidDeviceLifecycleTransition(device.lifecycleState, 'TRUSTED') ||
          device.lifecycleState !== 'ENROLLMENT_PENDING'
        ) {
          res.status(409).json({
            error: {
              code: 'INVALID_LIFECYCLE_TRANSITION',
              message: `Cannot confirm enrollment from state ${device.lifecycleState}.`,
            },
          });
          return;
        }

        const credentials = await repo.listCredentialsByDeviceId(device.id);
        const pendingCred = credentials.find((c) => c.status === 'PENDING_CONFIRMATION');
        if (!pendingCred) {
          res.status(400).json({
            error: {
              code: 'KEY_NOT_SUBMITTED',
              message:
                'Device has not submitted a verified public key proof-of-possession yet.',
            },
          });
          return;
        }

        // Optional fingerprint confirmation check if supplied by UI
        const expectedFingerprint = req.body?.publicKeyFingerprint;
        if (
          typeof expectedFingerprint === 'string' &&
          expectedFingerprint.trim().length > 0 &&
          expectedFingerprint.trim() !== pendingCred.publicKeyFingerprint
        ) {
          res.status(400).json({
            error: {
              code: 'FINGERPRINT_MISMATCH',
              message: 'Confirmed public key fingerprint does not match the pending device key.',
            },
          });
          return;
        }

        const now = new Date();
        const confirmed = await repo.confirmDeviceEnrollment({
          deviceId: device.id,
          confirmedAt: now,
        });

        const auditEnrolled = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: 'DEVICE_ENROLLED',
          metadata: {
            deviceId: device.id,
            deviceName: confirmed.device.name,
            deviceType: confirmed.device.deviceType,
            publicKeyFingerprint: confirmed.credential.publicKeyFingerprint,
            keyAlgorithm: confirmed.credential.keyAlgorithm,
          },
        });

        await repo.createNotification({
          userId: ctx.user.id,
          type: 'DEVICE_CONNECTED',
          severity: 'PROTECTED',
          category: 'Devices',
          title: `${confirmed.device.name} is now protected`,
          message: `You confirmed ${confirmed.device.name} and added it to your protected devices.`,
          relatedDeviceId: device.id,
          relatedDeviceName: confirmed.device.name,
          relatedEventId: auditEnrolled.id,
          actionLabel: 'View device',
          actionTarget: `device:${device.id}`,
        });

        ownerEventBroadcaster.emitToUser(ctx.user.id, 'DEVICE_CONNECTED', {
          deviceId: confirmed.device.id,
          deviceName: confirmed.device.name,
          deviceType: confirmed.device.deviceType,
          lifecycleState: confirmed.device.lifecycleState,
          publicKeyFingerprint: confirmed.credential.publicKeyFingerprint,
          status: 'CONNECTED',
          timestamp: now.toISOString(),
        });

        const updatedCreds = await repo.listCredentialsByDeviceId(device.id);
        res.status(200).json({
          device: toSafeDeviceDto(confirmed.device, updatedCreds),
        });
      } catch {
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to confirm device enrollment.',
          },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/enrollment/reject
   * Explicit owner rejection of a device awaiting approval.
   * Atomically transitions device to REVOKED and invalidates pending credentials.
   * Rejects cross-user or missing devices with 404 (anti-enumeration).
   */
  router.post(
    '/devices/:id/enrollment/reject',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const deviceId = String(req.params.id ?? '').trim();
        const device = await repo.findDeviceById(deviceId);

        // Anti-enumeration: 404 if device does not exist OR belongs to another user
        if (!device || device.userId !== ctx.user.id) {
          res.status(404).json({
            error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found.' },
          });
          return;
        }

        if (
          !isValidDeviceLifecycleTransition(device.lifecycleState, 'REVOKED') ||
          device.lifecycleState !== 'ENROLLMENT_PENDING'
        ) {
          res.status(409).json({
            error: {
              code: 'INVALID_LIFECYCLE_TRANSITION',
              message: `Cannot reject enrollment from state ${device.lifecycleState}.`,
            },
          });
          return;
        }

        const now = new Date();
        const rejected = await repo.rejectDeviceEnrollment({
          deviceId: device.id,
          revokedAt: now,
        });

        const auditRejected = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: 'DEVICE_ENROLLMENT_REJECTED',
          metadata: {
            deviceId: device.id,
            deviceName: rejected.device.name,
            deviceType: rejected.device.deviceType,
            publicKeyFingerprint: rejected.credential?.publicKeyFingerprint ?? null,
            reason: req.body?.reason ? String(req.body.reason).slice(0, 128) : 'OWNER_REJECTED',
          },
        });

        await repo.createNotification({
          userId: ctx.user.id,
          type: 'DEVICE_REJECTED',
          severity: 'ATTENTION',
          category: 'Devices',
          title: `Enrollment declined for ${rejected.device.name}`,
          message: `You declined the enrollment authorization request for ${rejected.device.name}.`,
          relatedDeviceId: device.id,
          relatedDeviceName: rejected.device.name,
          relatedEventId: auditRejected.id,
        });

        ownerEventBroadcaster.emitToUser(ctx.user.id, 'DEVICE_REJECTED', {
          deviceId: rejected.device.id,
          deviceName: rejected.device.name,
          deviceType: rejected.device.deviceType,
          lifecycleState: rejected.device.lifecycleState,
          status: 'REVOKED',
          timestamp: now.toISOString(),
        });

        const credentials = await repo.listCredentialsByDeviceId(device.id);
        res.status(200).json({
          status: 'REJECTED',
          device: toSafeDeviceDto(rejected.device, credentials),
        });
      } catch {
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to reject device enrollment.',
          },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/revoke
   * Permanently revokes a device and all of its active/pending cryptographic credentials.
   * A REVOKED device can NEVER transition back to TRUSTED or ACTIVE.
   */
  router.post(
    '/devices/:id/revoke',
    requireAuthenticatedUser,
    requireStepUp(STEP_UP_SCOPES.DEVICE_REVOKE),
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

        if (!isValidDeviceLifecycleTransition(device.lifecycleState, 'REVOKED')) {
          res.status(409).json({
            error: {
              code: 'INVALID_LIFECYCLE_TRANSITION',
              message: `Device in state ${device.lifecycleState} cannot transition to REVOKED.`,
            },
          });
          return;
        }

        const now = new Date();
        const consumed = await repo.consumeStepUp({
          sessionId: ctx.session.id,
          acceptableScopes: acceptableStepUpScopes(STEP_UP_SCOPES.DEVICE_REVOKE),
          now,
        });
        if (!consumed) {
          res.status(403).json({
            error: {
              code: 'STEP_UP_REQUIRED',
              message:
                'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
              requiredScope: STEP_UP_SCOPES.DEVICE_REVOKE,
            },
          });
          return;
        }

        const reason = sanitizeShortMetadata(req.body?.reason, 120) ?? 'USER_REVOKED';
        const revokedDevice = await repo.revokeDeviceAndCredentials({
          deviceId: device.id,
          revokedAt: now,
        });

        // Cancel any still-pending remote commands so no orphaned QUEUED/DELIVERED commands remain
        const pendingOnRevoke = await repo.listPendingCommandsForDevice(device.id);
        for (const pendingCmd of pendingOnRevoke) {
          await repo.updateRemoteCommandState({
            commandId: pendingCmd.id,
            status: 'CANCELLED',
            statusMessage: 'Cancelled automatically when device access was revoked.',
            completedAt: now,
          });
        }

        const auditRevoked = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: 'DEVICE_REVOKED',
          metadata: {
            deviceId: device.id,
            deviceName: device.name,
            previousState: device.lifecycleState,
            reason,
          },
        });

        await repo.createNotification({
          userId: ctx.user.id,
          type: 'DEVICE_DISCONNECTED',
          severity: 'WARNING',
          category: 'Devices',
          title: `${device.name} disconnected`,
          message: `Access for ${device.name} was permanently removed from your VAJRA account.`,
          relatedDeviceId: device.id,
          relatedDeviceName: device.name,
          relatedEventId: auditRevoked.id,
          actionLabel: 'View devices',
          actionTarget: 'devices',
        });

        const updatedCreds = await repo.listCredentialsByDeviceId(device.id);
        await repo.clearStepUp(ctx.session.id);
        res.status(200).json({
          device: toSafeDeviceDto(revokedDevice, updatedCreds),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke device.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/compromised
   * Flags a TRUSTED / ACTIVE / OFFLINE / LOST device as COMPROMISED.
   * Quarantines the device from Plane 2 authentication until it is revoked and re-enrolled.
   */
  router.post(
    '/devices/:id/compromised',
    requireAuthenticatedUser,
    requireStepUp(STEP_UP_SCOPES.DEVICE_COMPROMISED),
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

        if (!isValidDeviceLifecycleTransition(device.lifecycleState, 'COMPROMISED')) {
          res.status(409).json({
            error: {
              code: 'INVALID_LIFECYCLE_TRANSITION',
              message: `Device in state ${device.lifecycleState} cannot transition to COMPROMISED.`,
            },
          });
          return;
        }

        const now = new Date();
        const consumed = await repo.consumeStepUp({
          sessionId: ctx.session.id,
          acceptableScopes: acceptableStepUpScopes(STEP_UP_SCOPES.DEVICE_COMPROMISED),
          now,
        });
        if (!consumed) {
          res.status(403).json({
            error: {
              code: 'STEP_UP_REQUIRED',
              message:
                'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
              requiredScope: STEP_UP_SCOPES.DEVICE_COMPROMISED,
            },
          });
          return;
        }

        const reason = sanitizeShortMetadata(req.body?.reason, 120) ?? 'USER_FLAGGED_COMPROMISED';
        const updatedDevice = await repo.updateDeviceState({
          deviceId: device.id,
          lifecycleState: 'COMPROMISED',
          compromisedAt: now,
        });

        const auditCompromised = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: 'DEVICE_COMPROMISED_FLAGGED',
          metadata: {
            deviceId: device.id,
            deviceName: device.name,
            previousState: device.lifecycleState,
            reason,
          },
        });

        await repo.createNotification({
          userId: ctx.user.id,
          type: 'DEVICE_COMPROMISED',
          severity: 'CRITICAL',
          category: 'Needs Attention',
          title: `${device.name} needs your review`,
          message: `Trusted access for ${device.name} was paused after being flagged for security review.`,
          relatedDeviceId: device.id,
          relatedDeviceName: device.name,
          relatedEventId: auditCompromised.id,
          actionLabel: 'Review device',
          actionTarget: `device:${device.id}`,
        });

        const updatedCreds = await repo.listCredentialsByDeviceId(device.id);
        await repo.clearStepUp(ctx.session.id);
        res.status(200).json({
          device: toSafeDeviceDto(updatedDevice, updatedCreds),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to flag device as compromised.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/:id/decommission
   * Transitions an already REVOKED device to DECOMMISSIONED (archived).
   */
  router.post(
    '/devices/:id/decommission',
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

        if (!isValidDeviceLifecycleTransition(device.lifecycleState, 'DECOMMISSIONED')) {
          res.status(409).json({
            error: {
              code: 'INVALID_LIFECYCLE_TRANSITION',
              message: `Only a REVOKED or ENROLLMENT_PENDING device can transition to DECOMMISSIONED (current: ${device.lifecycleState}).`,
            },
          });
          return;
        }

        const decommissionedAt = new Date();
        await repo.revokeDeviceAndCredentials({
          deviceId: device.id,
          revokedAt: decommissionedAt,
        });
        const pendingOnDecommission = await repo.listPendingCommandsForDevice(device.id);
        for (const pendingCmd of pendingOnDecommission) {
          await repo.updateRemoteCommandState({
            commandId: pendingCmd.id,
            status: 'CANCELLED',
            statusMessage: 'Cancelled automatically when device was decommissioned.',
            completedAt: decommissionedAt,
          });
        }
        const updatedDevice = await repo.updateDeviceState({
          deviceId: device.id,
          lifecycleState: 'DECOMMISSIONED',
          connectivityStatus: 'OFFLINE',
        });

        await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          actorDeviceId: device.id,
          eventType: 'DEVICE_DECOMMISSIONED',
          metadata: {
            deviceId: device.id,
            deviceName: device.name,
          },
        });

        const updatedCreds = await repo.listCredentialsByDeviceId(device.id);
        res.status(200).json({
          device: toSafeDeviceDto(updatedDevice, updatedCreds),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to decommission device.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/auth/verify
   * Plane 2 Cryptographic Device Authentication Verification Endpoint.
   * Requires valid `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, and `X-Vajra-Signature`.
   * If the device is in `TRUSTED` or `OFFLINE` state, a valid signed Plane 2 verification transitions it to `ACTIVE`.
   */
  router.post(
    '/devices/auth/verify',
    requireTrustedDevice,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const dCtx = req.deviceAuthContext!;
        const now = new Date();

        let currentDevice = dCtx.device;
        if (
          currentDevice.lifecycleState === 'TRUSTED' ||
          currentDevice.lifecycleState === 'OFFLINE'
        ) {
          currentDevice = await repo.updateDeviceState({
            deviceId: currentDevice.id,
            lifecycleState: 'ACTIVE',
            connectivityStatus: 'ONLINE',
            lastSeenAt: now,
          });
        } else {
          currentDevice = await repo.updateDeviceState({
            deviceId: currentDevice.id,
            lifecycleState: currentDevice.lifecycleState,
            connectivityStatus: 'ONLINE',
            lastSeenAt: now,
          });
        }

        await repo.appendAuditEvent({
          actorUserId: currentDevice.userId,
          actorDeviceId: currentDevice.id,
          eventType: 'DEVICE_AUTH_VERIFIED',
          metadata: {
            deviceId: currentDevice.id,
            keyAlgorithm: dCtx.credential.keyAlgorithm,
            publicKeyFingerprint: dCtx.credential.publicKeyFingerprint,
            lifecycleState: currentDevice.lifecycleState,
          },
        });

        res.status(200).json({
          authenticated: true,
          principalLevel: dCtx.principalLevel,
          deviceId: currentDevice.id,
          lifecycleState: currentDevice.lifecycleState,
          publicKeyFingerprint: dCtx.credential.publicKeyFingerprint,
          verifiedAt: now.toISOString(),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Device verification failed.' },
        });
      }
    }
  );

  /**
   * POST /api/devices/credentials/rotate
   * Plane 2 Cryptographic Key Rotation Endpoint.
   * Authenticated by the currently active device key (`requireTrustedDevice`),
   * AND requires a valid Proof-of-Possession signature from the NEW keypair over the rotation transcript.
   */
  router.post(
    '/devices/credentials/rotate',
    requireTrustedDevice,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const dCtx = req.deviceAuthContext!;
        const newPublicKeyPem = req.body?.newPublicKeyPem;
        const newKeyAlgorithm = req.body?.newKeyAlgorithm as SupportedKeyAlgorithm | undefined;
        const newKeyProofSignature = req.body?.newKeyProofSignature;
        const rotationNonce = req.body?.rotationNonce;

        const now = new Date();
        // Verify Proof-of-Possession of the NEW private key using verifyEnrollmentProof with purpose token "ROTATE:<oldFingerprint>"
        const proofCheck = verifyEnrollmentProof({
          publicKeyPem: typeof newPublicKeyPem === 'string' ? newPublicKeyPem : '',
          expectedAlgorithm: newKeyAlgorithm,
          signatureBase64:
            typeof newKeyProofSignature === 'string' ? newKeyProofSignature : '',
          deviceId: dCtx.device.id,
          enrollmentToken: `ROTATE:${dCtx.credential.publicKeyFingerprint}`,
          challengeNonce: dCtx.nonce,
          timestampIso: dCtx.timestampIso,
          clientNonce: typeof rotationNonce === 'string' ? rotationNonce : '',
          nowMs: now.getTime(),
        });

        if (
          !proofCheck.valid ||
          !proofCheck.keyAlgorithm ||
          !proofCheck.publicKeyFingerprint ||
          !proofCheck.normalizedPublicKeyPem
        ) {
          res.status(400).json({
            error: {
              code: 'NEW_KEY_PROOF_INVALID',
              message:
                proofCheck.error ??
                'Proof-of-possession signature for the new device key is invalid.',
            },
          });
          return;
        }

        const existingCred = await repo.findCredentialByFingerprint(
          proofCheck.publicKeyFingerprint
        );
        if (existingCred) {
          res.status(409).json({
            error: {
              code: 'DUPLICATE_PUBLIC_KEY',
              message: 'New public key fingerprint is already registered.',
            },
          });
          return;
        }

        const rotated = await repo.rotateDeviceCredential({
          deviceId: dCtx.device.id,
          keyAlgorithm: proofCheck.keyAlgorithm,
          publicKeyPem: proofCheck.normalizedPublicKeyPem,
          publicKeyFingerprint: proofCheck.publicKeyFingerprint,
          hardwareBacked: Boolean(req.body?.hardwareBacked ?? dCtx.credential.hardwareBacked),
          rotatedAt: now,
        });

        await repo.appendAuditEvent({
          actorUserId: dCtx.device.userId,
          actorDeviceId: dCtx.device.id,
          eventType: 'DEVICE_KEY_ROTATED',
          metadata: {
            deviceId: dCtx.device.id,
            previousFingerprint: dCtx.credential.publicKeyFingerprint,
            newFingerprint: rotated.activeCredential.publicKeyFingerprint,
            keyAlgorithm: rotated.activeCredential.keyAlgorithm,
          },
        });

        const allCreds = await repo.listCredentialsByDeviceId(dCtx.device.id);
        res.status(200).json({
          rotated: true,
          device: toSafeDeviceDto(rotated.device, allCreds),
          activeCredential: toSafeDeviceCredentialDto(rotated.activeCredential),
        });
      } catch {
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Failed to rotate device cryptographic key.',
          },
        });
      }
    }
  );

  return router;
}
