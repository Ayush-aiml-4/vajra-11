/**
 * VAJRA — Authentication, MFA, Recovery Codes, Session & Audit Routes
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Security Rules Enforced:
 * - Generic authentication error messages ("Invalid credentials.") to prevent user enumeration
 * - Dummy Argon2id verification on unknown email to equalize response timing
 * - Temporary account lockout (15 minutes) after 5 consecutive failed attempts
 * - Never creates a privileged session after only a password if MFA (`totpEnabled`) is true
 * - TOTP secret is encrypted with AES-256-GCM; MFA is NOT marked enabled until verified
 * - Recovery codes are returned in plaintext ONLY once during generation/regeneration
 * - Explicit response DTOs: NEVER returns passwordHash, totpSecretEncrypted, recoveryCodeHashes, or raw session tokens
 */

import crypto from 'node:crypto';
import { Router, Request, Response } from 'express';
import QRCode from 'qrcode';
import {
  hashPassword,
  verifyPassword,
  getDummyPasswordHash,
  generateTotpSecret,
  buildTotpProvisioningUri,
  verifyTotpCode,
  encryptTotpSecret,
  decryptTotpSecret,
  generateRecoveryCodes,
  verifyAndConsumeRecoveryCode,
  generateSessionTokenPair,
  SESSION_IDLE_TTL_MS,
  SESSION_ABSOLUTE_TTL_MS,
  verifyAuditChain,
} from '../../../packages/security/src/node.ts';
import { IdentityRepository, UserEntity } from '../db/repository.ts';
import { SecurityEventEngine } from '../events/engine.ts';
import {
  validateEmailInput,
  validateDisplayNameInput,
  validatePasswordInput,
  validateTotpCodeInput,
  validateRecoveryCodeInput,
} from './validation.ts';
import { SlidingWindowRateLimiter } from './rate-limiter.ts';
import {
  setSessionCookie,
  clearSessionCookies,
  isTrustedProxyRequest,
  requireAuthenticatedUser,
  STEP_UP_TTL_MS,
  STEP_UP_SCOPES,
  StepUpScope,
} from './middleware.ts';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

export interface AuthRouterOptions {
  repository: IdentityRepository;
  totpEncryptionKey?: string;
}

/**
 * Maps internal UserEntity + MFA status to a safe public DTO.
 * Never includes passwordHash, totpSecretEncrypted, recoveryCodeHashes, or session tokens.
 */
export function toSafeUserDto(user: UserEntity, mfaEnabled: boolean) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    status: user.status,
    mfaEnabled,
    createdAt: user.createdAt.toISOString(),
    lastLoginAt: user.lastLoginAt ? user.lastLoginAt.toISOString() : null,
  };
}

export function getClientIpTruncated(req: Request): string {
  const forwarded = isTrustedProxyRequest(req)
    ? req.headers['x-forwarded-for']
    : undefined;
  const rawCandidate =
    typeof forwarded === 'string' && forwarded.trim().length > 0
      ? forwarded.split(',')[0].trim()
      : req.socket?.remoteAddress ?? '0.0.0.0';
  const rawIp = rawCandidate.startsWith('::ffff:')
    ? rawCandidate.slice('::ffff:'.length)
    : rawCandidate;

  if (rawIp.includes('.')) {
    const parts = rawIp.split('.');
    if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  }
  if (rawIp.includes(':')) {
    const groups = rawIp.split(':').slice(0, 4).join(':');
    return `${groups || '::'}::/64`;
  }
  return 'ip-redacted';
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();
  const repo = options.repository;
  const eventEngine = new SecurityEventEngine(repo);

  // Dedicated 256-bit key material for AES-256-GCM TOTP secret encryption.
  // In production, validateRuntimeConfig requires TOTP_ENCRYPTION_KEY >= 32 chars in env.
  // In development/test, if unset, an ephemeral per-process random key is generated (never a hardcoded secret).
  const ephemeralDevTotpKey = crypto.randomBytes(32).toString('hex');
  const getTotpEncryptionKey = (): string => {
    const configured = options.totpEncryptionKey ?? process.env.TOTP_ENCRYPTION_KEY;
    if (configured && configured.trim().length >= 16) {
      return configured.trim();
    }
    return ephemeralDevTotpKey;
  };

  const loginRateLimiter = new SlidingWindowRateLimiter({
    maxAttempts: 10,
    windowMs: 15 * 60 * 1000,
  });

  const mfaRateLimiter = new SlidingWindowRateLimiter({
    maxAttempts: 8,
    windowMs: 15 * 60 * 1000,
  });

  /**
   * POST /api/auth/register
   * Creates a new user account with an Argon2id password hash.
   */
  router.post('/auth/register', async (req: Request, res: Response): Promise<void> => {
    try {
      const emailCheck = validateEmailInput(req.body?.email);
      if (!emailCheck.valid || !emailCheck.normalizedEmail) {
        res.status(400).json({
          error: { code: 'INVALID_INPUT', message: emailCheck.error ?? 'Invalid email.' },
        });
        return;
      }

      const nameCheck = validateDisplayNameInput(req.body?.displayName);
      if (!nameCheck.valid || !nameCheck.sanitizedName) {
        res.status(400).json({
          error: { code: 'INVALID_INPUT', message: nameCheck.error ?? 'Invalid display name.' },
        });
        return;
      }

      const passwordCheck = validatePasswordInput(req.body?.password);
      if (!passwordCheck.valid) {
        res.status(400).json({
          error: { code: 'INVALID_INPUT', message: passwordCheck.error ?? 'Invalid password.' },
        });
        return;
      }

      const existing = await repo.findUserByEmail(emailCheck.normalizedEmail);
      if (existing) {
        res.status(409).json({
          error: {
            code: 'REGISTRATION_FAILED',
            message: 'Unable to register account with the provided details.',
          },
        });
        return;
      }

      const passwordHash = await hashPassword(req.body.password as string);
      const { user, credential } = await repo.createUserWithCredential({
        email: emailCheck.normalizedEmail,
        displayName: nameCheck.sanitizedName,
        passwordHash,
      });

      const auditAccountCreated = await repo.appendAuditEvent({
        actorUserId: user.id,
        eventType: 'ACCOUNT_CREATED',
        metadata: {
          email: user.email,
          ip: getClientIpTruncated(req),
        },
      });

      await eventEngine.ingestEvent({
        userId: user.id,
        type: 'SIGN_IN_SUCCESS',
        source: 'AUTHENTICATION',
        title: 'VAJRA account created',
        description: 'Your personal security console was initialized and secured.',
        metadata: {
          accountCreated: true,
          ip: getClientIpTruncated(req),
        },
        correlationId: auditAccountCreated.id,
      });

      await repo.createNotification({
        userId: user.id,
        type: 'TWO_STEP_RECOMMENDED',
        severity: 'ATTENTION',
        category: 'Needs Attention',
        title: 'Enable two-step verification',
        message:
          'Add an authenticator app to protect your VAJRA console and recovery actions against unauthorized sign-in.',
        relatedEventId: auditAccountCreated.id,
        actionLabel: 'Set up two-step',
        actionTarget: 'settings:security',
      });

      await repo.createNotification({
        userId: user.id,
        type: 'SECURITY_CHECK',
        severity: 'PROTECTED',
        category: 'Security',
        title: 'VAJRA protection console ready',
        message:
          'Your personal security console is active. Connect your Windows PC or Android phone to enable device protection.',
        relatedEventId: auditAccountCreated.id,
        actionLabel: 'Connect a device',
        actionTarget: 'devices:connect',
      });

      // Automatically create an initial authenticated session for the newly created user
      const now = new Date();
      const tokenPair = generateSessionTokenPair();
      const expiresAt = new Date(now.getTime() + SESSION_IDLE_TTL_MS);
      const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS);

      await repo.createSession({
        userId: user.id,
        tokenHash: tokenPair.sessionTokenHash,
        csrfTokenHash: tokenPair.csrfTokenHash,
        mfaVerified: false,
        mfaVerifiedAt: null,
        stepUpVerifiedUntil: new Date(now.getTime() + 5 * 60 * 1000),
        ipAddressTruncated: getClientIpTruncated(req),
        userAgentSummary: (req.headers['user-agent'] ?? 'unknown').slice(0, 120),
        expiresAt,
        absoluteExpiresAt,
      });

      setSessionCookie(req, res, tokenPair.rawSessionToken, Math.floor(SESSION_IDLE_TTL_MS / 1000));

      res.status(201).json({
        authenticated: true,
        csrfToken: tokenPair.rawCsrfToken,
        user: toSafeUserDto(user, credential.totpEnabled),
      });
    } catch {
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Unable to complete registration.' },
      });
    }
  });

  /**
   * POST /api/auth/login
   * Authenticates email + password (and TOTP / recovery code when MFA is enabled).
   */
  router.post('/auth/login', async (req: Request, res: Response): Promise<void> => {
    try {
      const emailCheck = validateEmailInput(req.body?.email);
      const rawPassword = req.body?.password;

      if (!emailCheck.valid || !emailCheck.normalizedEmail || typeof rawPassword !== 'string' || rawPassword.length === 0) {
        res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Invalid credentials.' },
        });
        return;
      }

      const rateKey = `login:${getClientIpTruncated(req)}:${emailCheck.normalizedEmail}`;
      const rateStatus = loginRateLimiter.check(rateKey);
      if (!rateStatus.allowed) {
        res.setHeader('Retry-After', String(rateStatus.retryAfterSeconds));
        res.status(429).json({
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many authentication attempts. Please try again later.',
          },
        });
        return;
      }

      const user = await repo.findUserByEmail(emailCheck.normalizedEmail);
      const credential = user ? await repo.findCredentialByUserId(user.id) : null;

      // Equalize timing if user does not exist
      if (!user || !credential) {
        loginRateLimiter.recordAttempt(rateKey);
        const dummyHash = await getDummyPasswordHash();
        await verifyPassword(rawPassword, dummyHash);
        await repo.appendAuditEvent({
          actorUserId: null,
          eventType: 'LOGIN_FAILURE',
          metadata: {
            reason: 'USER_NOT_FOUND_OR_INVALID_CREDENTIALS',
            ip: getClientIpTruncated(req),
          },
        });
        res.status(401).json({
          error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
        });
        return;
      }

      const now = new Date();

      // Check account status and temporary lockout
      if (user.status === 'DISABLED') {
        res.status(401).json({
          error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
        });
        return;
      }

      if (user.lockedUntil && now < user.lockedUntil) {
        res.status(423).json({
          error: {
            code: 'ACCOUNT_LOCKED',
            message: 'Account is temporarily locked due to multiple failed sign-in attempts.',
          },
        });
        return;
      }

      const passwordMatches = await verifyPassword(rawPassword, credential.passwordHash);
      if (!passwordMatches) {
        loginRateLimiter.recordAttempt(rateKey);
        const nextFailedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = nextFailedAttempts >= MAX_FAILED_ATTEMPTS;
        const lockedUntil = shouldLock ? new Date(now.getTime() + LOCKOUT_DURATION_MS) : null;

        await repo.updateUserLoginState({
          userId: user.id,
          failedLoginAttempts: nextFailedAttempts,
          lockedUntil,
          status: shouldLock ? 'LOCKED' : 'ACTIVE',
        });

        const auditFail = await repo.appendAuditEvent({
          actorUserId: user.id,
          eventType: 'LOGIN_FAILURE',
          metadata: {
            failedLoginAttempts: nextFailedAttempts,
            ip: getClientIpTruncated(req),
          },
        });

        await eventEngine.ingestEvent({
          userId: user.id,
          type: 'SIGN_IN_FAILURE',
          source: 'AUTHENTICATION',
          metadata: {
            failedLoginAttempts: nextFailedAttempts,
            ip: getClientIpTruncated(req),
          },
          correlationId: auditFail.id,
        });

        if (shouldLock) {
          const auditLock = await repo.appendAuditEvent({
            actorUserId: user.id,
            eventType: 'ACCOUNT_LOCKED',
            metadata: {
              lockedUntil: lockedUntil?.toISOString(),
              ip: getClientIpTruncated(req),
            },
          });

          await eventEngine.ingestEvent({
            userId: user.id,
            type: 'ACCOUNT_LOCKED',
            source: 'AUTHENTICATION',
            metadata: {
              lockedUntil: lockedUntil?.toISOString(),
              ip: getClientIpTruncated(req),
            },
            correlationId: auditLock.id,
          });
        }

        res.status(401).json({
          error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
        });
        return;
      }

      // If MFA is enabled, NEVER create a session from password alone!
      let mfaVerified = false;
      if (credential.totpEnabled) {
        const totpCode = req.body?.totpCode;
        const recoveryCode = req.body?.recoveryCode;

        if (!totpCode && !recoveryCode) {
          res.status(200).json({
            authenticated: false,
            mfaRequired: true,
            message: 'Multi-factor authentication code is required to complete sign-in.',
          });
          return;
        }

        const mfaRateKey = `mfa:${user.id}`;
        const mfaRate = mfaRateLimiter.check(mfaRateKey);
        if (!mfaRate.allowed) {
          res.status(429).json({
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Too many MFA verification attempts. Please wait before trying again.',
            },
          });
          return;
        }

        if (typeof recoveryCode === 'string' && recoveryCode.trim().length > 0) {
          const recValidation = validateRecoveryCodeInput(recoveryCode);
          if (!recValidation.valid) {
            mfaRateLimiter.recordAttempt(mfaRateKey);
            await repo.appendAuditEvent({
              actorUserId: user.id,
              eventType: 'MFA_VERIFICATION_FAILURE',
              metadata: { method: 'RECOVERY_CODE', reason: 'INVALID_FORMAT' },
            });
            res.status(401).json({
              error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
            });
            return;
          }

          const consumeResult = await repo.consumeRecoveryCodeAtomically({
            userId: user.id,
            rawRecoveryCode: recoveryCode,
            usedAtIso: now.toISOString(),
          });

          if (!consumeResult.valid) {
            mfaRateLimiter.recordAttempt(mfaRateKey);
            await repo.appendAuditEvent({
              actorUserId: user.id,
              eventType: 'MFA_VERIFICATION_FAILURE',
              metadata: { method: 'RECOVERY_CODE', reason: 'MISMATCH_OR_ALREADY_USED' },
            });
            res.status(401).json({
              error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
            });
            return;
          }

          mfaRateLimiter.reset(mfaRateKey);
          const revokedPriorSessions = await repo.revokeAllUserSessions(user.id);

          await repo.appendAuditEvent({
            actorUserId: user.id,
            eventType: 'RECOVERY_CODE_USED',
            metadata: {
              consumedCodeId: consumeResult.consumedCodeId,
              revokedPriorSessions,
              ip: getClientIpTruncated(req),
            },
          });
          mfaVerified = true;
        } else {
          const totpValidation = validateTotpCodeInput(totpCode);
          if (!totpValidation.valid || !totpValidation.normalizedCode || !credential.totpSecretEncrypted) {
            mfaRateLimiter.recordAttempt(mfaRateKey);
            await repo.appendAuditEvent({
              actorUserId: user.id,
              eventType: 'MFA_VERIFICATION_FAILURE',
              metadata: { method: 'TOTP', reason: 'INVALID_FORMAT' },
            });
            res.status(401).json({
              error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
            });
            return;
          }

          const secretBase32 = decryptTotpSecret({
            encryptedPayload: credential.totpSecretEncrypted,
            userId: user.id,
            encryptionKeyMaterial: getTotpEncryptionKey(),
          });

          const isValidTotp = verifyTotpCode({
            secretBase32,
            code: totpValidation.normalizedCode,
          });

          if (!isValidTotp) {
            mfaRateLimiter.recordAttempt(mfaRateKey);
            await repo.appendAuditEvent({
              actorUserId: user.id,
              eventType: 'MFA_VERIFICATION_FAILURE',
              metadata: { method: 'TOTP', reason: 'CODE_MISMATCH' },
            });
            res.status(401).json({
              error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
            });
            return;
          }
          mfaVerified = true;
        }

        mfaRateLimiter.reset(mfaRateKey);
      }

      // Reset failed login counter and create authenticated session
      loginRateLimiter.reset(rateKey);
      const updatedUser = await repo.updateUserLoginState({
        userId: user.id,
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: now,
        status: 'ACTIVE',
      });

      const tokenPair = generateSessionTokenPair();
      const expiresAt = new Date(now.getTime() + SESSION_IDLE_TTL_MS);
      const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS);

      await repo.createSession({
        userId: user.id,
        tokenHash: tokenPair.sessionTokenHash,
        csrfTokenHash: tokenPair.csrfTokenHash,
        mfaVerified,
        mfaVerifiedAt: mfaVerified ? now : null,
        stepUpVerifiedUntil: new Date(now.getTime() + 5 * 60 * 1000),
        ipAddressTruncated: getClientIpTruncated(req),
        userAgentSummary: (req.headers['user-agent'] ?? 'unknown').slice(0, 120),
        expiresAt,
        absoluteExpiresAt,
      });

      const auditLogin = await repo.appendAuditEvent({
        actorUserId: user.id,
        eventType: 'LOGIN_SUCCESS',
        metadata: {
          mfaVerified,
          ip: getClientIpTruncated(req),
        },
      });

      await eventEngine.ingestEvent({
        userId: user.id,
        type: 'SIGN_IN_SUCCESS',
        source: 'AUTHENTICATION',
        metadata: {
          mfaVerified,
          ip: getClientIpTruncated(req),
        },
        correlationId: auditLogin.id,
      });

      setSessionCookie(req, res, tokenPair.rawSessionToken, Math.floor(SESSION_IDLE_TTL_MS / 1000));

      res.status(200).json({
        authenticated: true,
        mfaRequired: false,
        csrfToken: tokenPair.rawCsrfToken,
        user: toSafeUserDto(updatedUser, credential.totpEnabled),
      });
    } catch {
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Authentication request failed.' },
      });
    }
  });

  /**
   * POST /api/auth/logout
   * Revokes the current session (or all sessions if `revokeAll: true`) and clears cookies.
   */
  router.post(
    '/auth/logout',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const revokeAll = Boolean(req.body?.revokeAll);

        if (revokeAll) {
          await repo.revokeAllUserSessions(ctx.user.id);
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'SESSION_REVOKED',
            metadata: { scope: 'ALL_USER_SESSIONS' },
          });
        } else {
          await repo.revokeSessionById(ctx.session.id);
        }

        const auditLogout = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'LOGOUT',
          metadata: { sessionId: ctx.session.id },
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          type: 'SIGN_OUT',
          source: 'AUTHENTICATION',
          metadata: { revokeAll },
          correlationId: auditLogout.id,
        });

        clearSessionCookies(req, res);
        res.status(200).json({ status: 'logged_out' });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Logout failed.' },
        });
      }
    }
  );

  /**
   * GET /api/auth/me
   * Returns the current authenticated user DTO without exposing any credential fields.
   */
  router.get('/auth/me', async (req: Request, res: Response): Promise<void> => {
    const ctx = req.authContext;
    if (!ctx) {
      res.status(401).json({
        authenticated: false,
        error: { code: 'UNAUTHENTICATED', message: 'Not signed in.' },
      });
      return;
    }

    const credential = await repo.findCredentialByUserId(ctx.user.id);
    const unusedRecoveryCodesCount = credential
      ? credential.recoveryCodeHashes.filter((r) => r.usedAt === null).length
      : 0;

    // Issue a fresh CSRF token tied to the current session if needed by the client SPA on reload
    const freshPair = generateSessionTokenPair();
    await repo.updateSessionActivityAndRotation({
      sessionId: ctx.session.id,
      newCsrfTokenHash: freshPair.csrfTokenHash,
      lastActiveAt: new Date(),
      expiresAt: ctx.session.expiresAt,
    });
    if (res.getHeader('X-Vajra-Csrf-Token')) {
      res.setHeader('X-Vajra-Csrf-Token', freshPair.rawCsrfToken);
    }

    res.status(200).json({
      authenticated: true,
      csrfToken: freshPair.rawCsrfToken,
      user: {
        ...toSafeUserDto(ctx.user, Boolean(credential?.totpEnabled)),
        unusedRecoveryCodesCount,
      },
    });
  });

  /**
   * POST /api/auth/mfa/setup
   * Generates a new TOTP secret, encrypts it with AES-256-GCM, and returns the provisioning URI + QR Data URL.
   * Does NOT enable MFA until verified via POST /api/auth/mfa/verify.
   */
  router.post(
    '/auth/mfa/setup',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential) {
          res.status(404).json({
            error: { code: 'NOT_FOUND', message: 'Credential record not found.' },
          });
          return;
        }

        if (credential.totpEnabled) {
          res.status(409).json({
            error: {
              code: 'MFA_ALREADY_ENABLED',
              message: 'TOTP MFA is already enabled for this account.',
            },
          });
          return;
        }

        const secretBase32 = generateTotpSecret();
        const encryptedSecret = encryptTotpSecret({
          secretBase32,
          userId: ctx.user.id,
          encryptionKeyMaterial: getTotpEncryptionKey(),
        });

        await repo.updateUserCredential({
          userId: ctx.user.id,
          totpSecretEncrypted: encryptedSecret,
          totpEnabled: false,
        });

        const provisioningUri = buildTotpProvisioningUri({
          secretBase32,
          accountEmail: ctx.user.email,
          issuer: 'VAJRA Security',
        });

        const qrCodeDataUrl = await QRCode.toDataURL(provisioningUri, {
          errorCorrectionLevel: 'M',
          margin: 2,
          width: 220,
        });

        await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'MFA_SETUP_STARTED',
          metadata: { method: 'TOTP' },
        });

        res.status(200).json({
          setupStarted: true,
          totpEnabled: false,
          secretBase32,
          provisioningUri,
          qrCodeDataUrl,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to initiate MFA setup.' },
        });
      }
    }
  );

  /**
   * POST /api/auth/mfa/verify
   * Verifies the 6-digit TOTP code against the pending encrypted secret, marks MFA enabled,
   * and returns a set of single-use recovery codes (shown only once).
   */
  router.post(
    '/auth/mfa/verify',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const codeCheck = validateTotpCodeInput(req.body?.code);
        if (!codeCheck.valid || !codeCheck.normalizedCode) {
          res.status(400).json({
            error: { code: 'INVALID_INPUT', message: codeCheck.error ?? 'Invalid TOTP code.' },
          });
          return;
        }

        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential || !credential.totpSecretEncrypted) {
          res.status(400).json({
            error: {
              code: 'MFA_SETUP_NOT_STARTED',
              message: 'Please initiate MFA setup before verifying.',
            },
          });
          return;
        }

        const secretBase32 = decryptTotpSecret({
          encryptedPayload: credential.totpSecretEncrypted,
          userId: ctx.user.id,
          encryptionKeyMaterial: getTotpEncryptionKey(),
        });

        const isValid = verifyTotpCode({
          secretBase32,
          code: codeCheck.normalizedCode,
        });

        if (!isValid) {
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'MFA_VERIFICATION_FAILURE',
            metadata: { phase: 'ENROLLMENT_VERIFY' },
          });
          res.status(400).json({
            error: {
              code: 'INVALID_TOTP_CODE',
              message: 'Verification code did not match. Please check your authenticator app.',
            },
          });
          return;
        }

        const recoveryBundle = generateRecoveryCodes(8);
        await repo.updateUserCredential({
          userId: ctx.user.id,
          totpEnabled: true,
          recoveryCodeHashes: recoveryBundle.storedRecords,
        });

        const auditMfaEnabled = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'MFA_ENABLED',
          metadata: {
            method: 'TOTP',
            recoveryCodesGenerated: recoveryBundle.plaintextCodes.length,
          },
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          type: 'MFA_ENABLED',
          source: 'AUTHENTICATION',
          metadata: {
            method: 'TOTP',
            recoveryCodesGenerated: recoveryBundle.plaintextCodes.length,
          },
          correlationId: auditMfaEnabled.id,
        });

        res.status(200).json({
          totpEnabled: true,
          recoveryCodes: recoveryBundle.plaintextCodes,
          warning:
            'Store these recovery codes in a safe place immediately. They are shown only once and cannot be retrieved again.',
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to verify MFA setup.' },
        });
      }
    }
  );

  /**
   * POST /api/auth/mfa/disable
   * Disables TOTP MFA after verifying the user's current password.
   */
  router.post(
    '/auth/mfa/disable',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const currentPassword = req.body?.currentPassword;
        if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
          res.status(400).json({
            error: {
              code: 'INVALID_INPUT',
              message: 'Current password is required to disable MFA.',
            },
          });
          return;
        }

        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential) {
          res.status(404).json({
            error: { code: 'NOT_FOUND', message: 'Credential record not found.' },
          });
          return;
        }

        const passwordMatches = await verifyPassword(currentPassword, credential.passwordHash);
        if (!passwordMatches) {
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'MFA_VERIFICATION_FAILURE',
            metadata: { action: 'MFA_DISABLE_PASSWORD_MISMATCH' },
          });
          res.status(401).json({
            error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
          });
          return;
        }

        await repo.updateUserCredential({
          userId: ctx.user.id,
          totpSecretEncrypted: null,
          totpEnabled: false,
          recoveryCodeHashes: [],
        });

        const revokedOtherSessions = await repo.revokeAllUserSessions(
          ctx.user.id,
          ctx.session.id
        );

        const auditMfaDisabled = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'MFA_DISABLED',
          metadata: { method: 'TOTP', revokedOtherSessions },
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          type: 'MFA_DISABLED',
          source: 'AUTHENTICATION',
          metadata: { method: 'TOTP' },
          correlationId: auditMfaDisabled.id,
        });

        res.status(200).json({
          totpEnabled: false,
          message: 'Multi-factor authentication has been disabled.',
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to disable MFA.' },
        });
      }
    }
  );

  /**
   * POST /api/auth/recovery-codes/regenerate
   * Regenerates 8 fresh single-use recovery codes (invalidating previous codes) after verifying current password.
   */
  router.post(
    '/auth/recovery-codes/regenerate',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const currentPassword = req.body?.currentPassword;
        if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
          res.status(400).json({
            error: {
              code: 'INVALID_INPUT',
              message: 'Current password is required to regenerate recovery codes.',
            },
          });
          return;
        }

        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential || !credential.totpEnabled) {
          res.status(400).json({
            error: {
              code: 'MFA_NOT_ENABLED',
              message: 'MFA must be enabled before generating recovery codes.',
            },
          });
          return;
        }

        const passwordMatches = await verifyPassword(currentPassword, credential.passwordHash);
        if (!passwordMatches) {
          res.status(401).json({
            error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
          });
          return;
        }

        const recoveryBundle = generateRecoveryCodes(8);
        await repo.updateUserCredential({
          userId: ctx.user.id,
          recoveryCodeHashes: recoveryBundle.storedRecords,
        });

        const revokedOtherSessions = await repo.revokeAllUserSessions(
          ctx.user.id,
          ctx.session.id
        );

        await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'RECOVERY_CODES_REGENERATED',
          metadata: { count: recoveryBundle.plaintextCodes.length, revokedOtherSessions },
        });

        res.status(200).json({
          recoveryCodes: recoveryBundle.plaintextCodes,
          warning:
            'Previous recovery codes have been invalidated. Store these new codes securely; they will not be shown again.',
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to regenerate recovery codes.' },
        });
      }
    }
  );

  /**
   * POST /api/auth/password/change
   * Changes the authenticated user's password, revokes other sessions, and writes an audit record.
   */
  router.post(
    '/auth/password/change',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const currentPassword = req.body?.currentPassword;
        const newPassword = req.body?.newPassword;

        if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
          res.status(400).json({
            error: { code: 'INVALID_INPUT', message: 'Current password is required.' },
          });
          return;
        }

        const newPolicy = validatePasswordInput(newPassword);
        if (!newPolicy.valid) {
          res.status(400).json({
            error: { code: 'INVALID_INPUT', message: newPolicy.error ?? 'Invalid new password.' },
          });
          return;
        }

        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential) {
          res.status(404).json({
            error: { code: 'NOT_FOUND', message: 'Credential record not found.' },
          });
          return;
        }

        const matches = await verifyPassword(currentPassword, credential.passwordHash);
        if (!matches) {
          res.status(401).json({
            error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' },
          });
          return;
        }

        const newHash = await hashPassword(newPassword as string);
        const now = new Date();
        await repo.updateUserCredential({
          userId: ctx.user.id,
          passwordHash: newHash,
          passwordChangedAt: now,
        });

        // Invalidate all other sessions for this user
        const revokedOtherCount = await repo.revokeAllUserSessions(ctx.user.id, ctx.session.id);

        const auditPwdChanged = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'PASSWORD_CHANGED',
          metadata: { revokedOtherSessions: revokedOtherCount },
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          type: 'PASSWORD_CHANGED',
          source: 'AUTHENTICATION',
          metadata: { revokedOtherSessions: revokedOtherCount },
          correlationId: auditPwdChanged.id,
        });

        if (revokedOtherCount > 0) {
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'SESSION_REVOKED',
            metadata: { reason: 'PASSWORD_CHANGED', count: revokedOtherCount },
          });
        }

        res.status(200).json({
          status: 'password_changed',
          revokedOtherSessions: revokedOtherCount,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to change password.' },
        });
      }
    }
  );

  /**
   * GET /api/auth/sessions
   * Lists active, non-revoked, non-expired sessions for the authenticated user without exposing token hashes.
   */
  router.get(
    '/auth/sessions',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const activeSessions = await repo.listActiveUserSessions(ctx.user.id, new Date());

        res.status(200).json({
          sessions: activeSessions.map((s) => ({
            id: s.id,
            sessionType: s.sessionType,
            isCurrent: s.id === ctx.session.id,
            mfaVerified: s.mfaVerified,
            mfaVerifiedAt: s.mfaVerifiedAt ? s.mfaVerifiedAt.toISOString() : null,
            ipAddressTruncated: s.ipAddressTruncated,
            userAgentSummary: s.userAgentSummary,
            createdAt: s.createdAt.toISOString(),
            lastActiveAt: s.lastActiveAt.toISOString(),
            expiresAt: s.expiresAt.toISOString(),
            absoluteExpiresAt: s.absoluteExpiresAt.toISOString(),
          })),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve active sessions.' },
        });
      }
    }
  );

  /**
   * POST /api/auth/sessions/:sessionId/revoke
   * Revokes a specific session belonging to the authenticated user.
   * If the user revokes their current session, clears session cookies as well.
   */
  router.post(
    '/auth/sessions/:sessionId/revoke',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const targetSessionId = String(req.params.sessionId ?? '').trim();
        if (!targetSessionId || targetSessionId.length > 64) {
          res.status(400).json({
            error: { code: 'INVALID_SESSION_ID', message: 'Invalid session identifier.' },
          });
          return;
        }

        const revoked = await repo.revokeUserSessionById({
          userId: ctx.user.id,
          sessionId: targetSessionId,
        });

        if (!revoked) {
          res.status(404).json({
            error: { code: 'SESSION_NOT_FOUND', message: 'Active session not found.' },
          });
          return;
        }

        const revokedCurrent = targetSessionId === ctx.session.id;

        const auditRevoke = await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'SESSION_REVOKED',
          metadata: {
            scope: revokedCurrent ? 'CURRENT_SESSION' : 'SINGLE_SESSION',
            revokedSessionId: targetSessionId,
          },
        });

        await eventEngine.ingestEvent({
          userId: ctx.user.id,
          type: 'SESSION_REVOKED',
          source: 'AUTHENTICATION',
          metadata: {
            revokedCurrent,
            revokedSessionId: targetSessionId,
          },
          correlationId: auditRevoke.id,
        });

        if (revokedCurrent) {
          clearSessionCookies(req, res);
        }

        res.status(200).json({
          status: 'session_revoked',
          sessionId: targetSessionId,
          revokedCurrent,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke session.' },
        });
      }
    }
  );

  /**
   * GET /api/audit
   * Returns the authenticated user's audit events and verifies the global hash chain integrity.
   */
  router.get(
    '/audit',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const entries = await repo.listAuditEvents({
          actorUserId: ctx.user.id,
          limit: 50,
        });
        const allOrdered = await repo.getAllAuditEventsOrdered();
        const chainVerification = verifyAuditChain(allOrdered);

        res.status(200).json({
          entries,
          chainVerification,
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve audit log.' },
        });
      }
    }
  );

  const handleAuditVerify = async (req: Request, res: Response): Promise<void> => {
    try {
      const ctx = req.authContext!;
      const allOrdered = await repo.getAllAuditEventsOrdered();
      const chainVerification = verifyAuditChain(allOrdered);
      const userEventCount = allOrdered.filter((e) => e.actorUserId === ctx.user.id).length;

      res.status(200).json({
        verification: {
          ...chainVerification,
          verifiedAt: new Date().toISOString(),
          userEventCount,
        },
      });
    } catch {
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to verify audit log integrity.' },
      });
    }
  };

  /**
   * GET & POST /api/audit/verify
   * Dedicated cryptographic hash-chain integrity verification endpoint for the tamper-evident audit log.
   */
  router.get('/audit/verify', requireAuthenticatedUser, handleAuditVerify);
  router.post('/audit/verify', requireAuthenticatedUser, handleAuditVerify);

  /**
   * POST /api/auth/step-up
   * Server-side TOTP verification that grants a short-lived, session-bound,
   * action-scoped step-up authorization. Never accepts a client boolean/timestamp.
   * Protected by existing CSRF + Origin checks via requireAuthenticatedUser.
   */
  router.post(
    '/auth/step-up',
    requireAuthenticatedUser,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const ctx = req.authContext!;
        const rawScope = String(req.body?.actionScope ?? '').trim().toUpperCase();
        const allowedScopes = Object.values(STEP_UP_SCOPES) as string[];
        if (!allowedScopes.includes(rawScope)) {
          res.status(400).json({
            error: {
              code: 'INVALID_STEP_UP_SCOPE',
              message: `actionScope must be one of: ${allowedScopes.join(', ')}`,
            },
          });
          return;
        }
        const actionScope = rawScope as StepUpScope;

        const stepUpRateKey = `stepup:${ctx.user.id}`;
        const stepUpRateStatus = mfaRateLimiter.check(stepUpRateKey);
        if (!stepUpRateStatus.allowed) {
          res.status(429).json({
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Too many MFA step-up attempts. Please wait before trying again.',
            },
          });
          return;
        }

        const credential = await repo.findCredentialByUserId(ctx.user.id);
        if (!credential || !credential.totpEnabled || !credential.totpSecretEncrypted) {
          res.status(400).json({
            error: {
              code: 'MFA_NOT_ENABLED',
              message: 'Multi-factor authentication must be enabled before step-up verification.',
            },
          });
          return;
        }

        const codeCheck = validateTotpCodeInput(req.body?.totpCode ?? req.body?.code);
        if (!codeCheck.valid || !codeCheck.normalizedCode) {
          mfaRateLimiter.recordAttempt(stepUpRateKey);
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'STEP_UP_VERIFICATION_FAILURE',
            metadata: { reason: 'INVALID_CODE_FORMAT', actionScope },
          });
          res.status(401).json({
            error: {
              code: 'INVALID_TOTP_CODE',
              message: 'Invalid or missing TOTP code.',
            },
          });
          return;
        }

        const secretBase32 = decryptTotpSecret({
          encryptedPayload: credential.totpSecretEncrypted,
          userId: ctx.user.id,
          encryptionKeyMaterial: getTotpEncryptionKey(),
        });
        const isValid = verifyTotpCode({
          secretBase32,
          code: codeCheck.normalizedCode,
        });
        if (!isValid) {
          mfaRateLimiter.recordAttempt(stepUpRateKey);
          await repo.appendAuditEvent({
            actorUserId: ctx.user.id,
            eventType: 'STEP_UP_VERIFICATION_FAILURE',
            metadata: { reason: 'TOTP_MISMATCH', actionScope },
          });
          res.status(401).json({
            error: {
              code: 'INVALID_TOTP_CODE',
              message: 'Invalid TOTP code.',
            },
          });
          return;
        }

        mfaRateLimiter.reset(stepUpRateKey);
        const now = new Date();
        const stepUpUntil = new Date(now.getTime() + STEP_UP_TTL_MS);
        const updatedSession = await repo.grantStepUp({
          sessionId: ctx.session.id,
          stepUpVerifiedUntil: stepUpUntil,
          stepUpActionScope: actionScope,
        });

        await repo.appendAuditEvent({
          actorUserId: ctx.user.id,
          eventType: 'STEP_UP_VERIFIED',
          metadata: {
            actionScope,
            stepUpVerifiedUntil: stepUpUntil.toISOString(),
            sessionId: ctx.session.id,
          },
        });

        res.status(200).json({
          stepUpVerified: true,
          actionScope,
          stepUpVerifiedUntil: updatedSession.stepUpVerifiedUntil?.toISOString() ?? stepUpUntil.toISOString(),
          expiresInSeconds: Math.floor(STEP_UP_TTL_MS / 1000),
        });
      } catch {
        res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Step-up verification failed.' },
        });
      }
    }
  );

  return router;
}
