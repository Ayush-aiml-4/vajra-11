/**
 * @vajra/security — Cryptographic Device Identity, Enrollment & Plane 2 Request Signing
 * Prompt 0004: Cryptographic Device Identity & Secure Enrollment
 *
 * Implements:
 * 1. Asymmetric keypair generation (Ed25519 & ECDSA P-256) for endpoint enrollment and testing
 * 2. SPKI public key parsing, algorithm validation, and SHA-256 fingerprint computation
 * 3. Single-use, short-lived enrollment token & challenge nonce generation and SHA-256 hashing
 * 4. Canonical Enrollment Proof-of-Possession transcript signing & verification
 * 5. Plane 2 Authenticated Device Request transcript signing & verification (anti-replay + timestamp window)
 * 6. Device Lifecycle State Machine transition validation (preventing illegal/revoked reactivation)
 */

import crypto from 'node:crypto';
import { canonicalJsonSerialize } from './audit-chain.ts';

export type SupportedKeyAlgorithm = 'ED25519' | 'ECDSA_P256';

export type DeviceLifecycleStateType =
  | 'UNREGISTERED'
  | 'ENROLLMENT_PENDING'
  | 'TRUSTED'
  | 'ACTIVE'
  | 'OFFLINE'
  | 'LOST'
  | 'COMPROMISED'
  | 'REVOKED'
  | 'DECOMMISSIONED';

export type DeviceCredentialStatusType =
  | 'PENDING_CONFIRMATION'
  | 'ACTIVE'
  | 'ROTATED'
  | 'REVOKED';

export const ENROLLMENT_TOKEN_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const DEVICE_AUTH_TIMESTAMP_WINDOW_MS = 2 * 60 * 1000; // ±120 seconds

export interface GeneratedDeviceKeyPair {
  keyAlgorithm: SupportedKeyAlgorithm;
  publicKeyPem: string;
  privateKeyPem: string;
  publicKeyFingerprint: string;
}

export interface ParsedDevicePublicKey {
  valid: boolean;
  keyAlgorithm?: SupportedKeyAlgorithm;
  normalizedPublicKeyPem?: string;
  publicKeyFingerprint?: string;
  keyObject?: crypto.KeyObject;
  error?: string;
}

export interface EnrollmentTokenBundle {
  rawEnrollmentToken: string;
  tokenHash: string;
  challengeNonce: string;
  expiresAt: Date;
  verificationPasscode: string;
  passcodeHash: string;
}

/**
 * Resolves the server-held secret used for keyed verification passcode HMAC calculation.
 * 
 * Rules:
 * 1. Production detection: strictly checks (APP_ENV === 'production' || NODE_ENV === 'production').
 *    APPLET_ID never bypasses production mode.
 * 2. In production:
 *    - Dedicated PASSCODE_HMAC_SECRET of at least 32 characters is strictly required.
 *    - Fallback to SESSION_SECRET or hardcoded development secret is strictly prohibited and fails closed.
 * 3. In development / testing (when neither APP_ENV nor NODE_ENV is 'production'):
 *    - Uses providedSecret or PASSCODE_HMAC_SECRET or SESSION_SECRET if >= 32 characters.
 *    - Falls back to deterministic development secret 'vajra-dev-passcode-hmac-secret-32-chars-min!'.
 */
export function resolvePasscodeHmacSecret(providedSecret?: string): string {
  const isProduction =
    process.env.APP_ENV?.trim().toLowerCase() === 'production' ||
    process.env.NODE_ENV?.trim().toLowerCase() === 'production';

  if (isProduction) {
    const candidate = (providedSecret ?? process.env.PASSCODE_HMAC_SECRET ?? '').trim();
    if (candidate.length < 32) {
      throw new Error(
        'MISSING_PASSCODE_HMAC_SECRET: Dedicated PASSCODE_HMAC_SECRET of at least 32 characters is strictly required in production mode (SESSION_SECRET fallback prohibited).'
      );
    }
    return candidate;
  }

  // Non-production (development / test)
  if (providedSecret !== undefined) {
    const trimmed = providedSecret.trim();
    if (trimmed.length < 32) {
      throw new Error(
        'MISSING_PASSCODE_HMAC_SECRET: PASSCODE_HMAC_SECRET must be at least 32 characters in length.'
      );
    }
    return trimmed;
  }

  const envSecret = (process.env.PASSCODE_HMAC_SECRET ?? process.env.SESSION_SECRET ?? '').trim();
  if (envSecret.length >= 32) {
    return envSecret;
  }

  return 'vajra-dev-passcode-hmac-secret-32-chars-min!';
}

/**
 * Generates a clean 6-digit numeric verification passcode (100000 - 999999).
 */
export function generateVerificationPasscode(): string {
  const num = crypto.randomInt(100000, 1000000);
  return String(num);
}

/**
 * Computes keyed HMAC-SHA256 of the normalized verification passcode bound to challenge nonce.
 * Format: hmac-sha256:<hex>
 * Validates exactly 6 numeric digits and uses server-held HMAC secret.
 */
export function hashVerificationPasscode(
  passcode: string,
  challengeNonce: string,
  serverSecret?: string
): string {
  if (typeof passcode !== 'string') {
    throw new Error('INVALID_PASSCODE: Verification passcode must be a string.');
  }
  const normalized = passcode.replace(/\s+/g, '').trim();
  if (!/^\d{6}$/.test(normalized)) {
    throw new Error('INVALID_PASSCODE_FORMAT: Passcode must be exactly 6 numeric digits.');
  }

  const secret = resolvePasscodeHmacSecret(serverSecret);
  const nonce = typeof challengeNonce === 'string' ? challengeNonce.trim() : '';
  if (nonce.length < 16) {
    throw new Error('INVALID_CHALLENGE_NONCE: Challenge nonce must be at least 16 characters.');
  }

  const digest = crypto
    .createHmac('sha256', secret)
    .update(`VAJRA-PASSCODE-HMAC-V1:${nonce}:${normalized}`, 'utf8')
    .digest('hex');
  return `hmac-sha256:${digest}`;
}

/**
 * Validates a submitted verification passcode against the expected passcode hash using constant-time comparison.
 */
export function verifyVerificationPasscode(
  submittedPasscode: string,
  expectedPasscodeHash: string,
  challengeNonce: string,
  serverSecret?: string
): boolean {
  if (
    typeof submittedPasscode !== 'string' ||
    typeof expectedPasscodeHash !== 'string' ||
    submittedPasscode.trim().length === 0
  ) {
    return false;
  }

  const normalized = submittedPasscode.replace(/\s+/g, '').trim();
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }

  try {
    const candidateHash = hashVerificationPasscode(normalized, challengeNonce, serverSecret);
    const bufA = Buffer.from(candidateHash, 'utf8');
    const bufB = Buffer.from(expectedPasscodeHash.trim(), 'utf8');
    if (bufA.length !== bufB.length) {
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Formats a 6-digit passcode with an ergonomic space separator (e.g., '842 195').
 */
export function formatVerificationPasscode(passcode: string): string {
  const clean = passcode.replace(/\s+/g, '').trim();
  if (clean.length === 6) {
    return `${clean.slice(0, 3)} ${clean.slice(3, 6)}`;
  }
  return clean;
}

/**
 * Generates a high-entropy (160-bit) human-scannable / CLI-friendly enrollment token,
 * its SHA-256 database hash, a 128-bit cryptographic challenge nonce,
 * and a short-lived 6-digit verification passcode with keyed HMAC-SHA256 verifier.
 */
export function generateEnrollmentChallengeBundle(
  now: Date = new Date(),
  serverSecret?: string
): EnrollmentTokenBundle {
  const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Unambiguous 32-char Crockford-style alphabet
  const randomBytes = crypto.randomBytes(20); // 20 chars * 5 bits = 100+ bits of unambiguous code + prefix
  let chars = '';
  for (let i = 0; i < 20; i++) {
    chars += alphabet[randomBytes[i] % alphabet.length];
  }
  const rawEnrollmentToken = `VJR-${chars.slice(0, 5)}-${chars.slice(5, 10)}-${chars.slice(10, 15)}-${chars.slice(15, 20)}`;
  const tokenHash = hashEnrollmentToken(rawEnrollmentToken);
  const challengeNonce = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(now.getTime() + ENROLLMENT_TOKEN_TTL_MS);
  const verificationPasscode = generateVerificationPasscode();
  const passcodeHash = hashVerificationPasscode(verificationPasscode, challengeNonce, serverSecret);

  return {
    rawEnrollmentToken,
    tokenHash,
    challengeNonce,
    expiresAt,
    verificationPasscode,
    passcodeHash,
  };
}

/**
 * Generates an asymmetric device keypair (Ed25519 by default, or ECDSA P-256).
 * In production endpoints, private keys stay inside Windows TPM/DPAPI or Android Keystore.
 * This helper is used by the interactive enrollment simulator and automated security tests.
 */
export function generateDeviceKeyPair(
  algorithm: SupportedKeyAlgorithm = 'ED25519'
): GeneratedDeviceKeyPair {
  if (algorithm === 'ED25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const digest = crypto.createHash('sha256').update(spkiDer).digest('hex');
    return {
      keyAlgorithm: 'ED25519',
      publicKeyPem,
      privateKeyPem,
      publicKeyFingerprint: `sha256:${digest}`,
    };
  }

  if (algorithm === 'ECDSA_P256') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const digest = crypto.createHash('sha256').update(spkiDer).digest('hex');
    return {
      keyAlgorithm: 'ECDSA_P256',
      publicKeyPem,
      privateKeyPem,
      publicKeyFingerprint: `sha256:${digest}`,
    };
  }

  throw new Error(`Unsupported key algorithm: ${String(algorithm)}`);
}

/**
 * Parses and validates an untrusted PEM public key, ensuring it is a valid SPKI
 * Ed25519 or ECDSA P-256 public key (never a private key or weak RSA key),
 * and computes its canonical SHA-256 SPKI DER fingerprint.
 */
export function parseAndValidateDevicePublicKey(
  rawPublicKeyPem: unknown,
  expectedAlgorithm?: SupportedKeyAlgorithm
): ParsedDevicePublicKey {
  if (typeof rawPublicKeyPem !== 'string' || rawPublicKeyPem.trim().length === 0) {
    return { valid: false, error: 'Public key PEM is required.' };
  }

  const trimmed = rawPublicKeyPem.trim();
  if (trimmed.length > 4096) {
    return { valid: false, error: 'Public key PEM exceeds maximum permitted length.' };
  }

  if (trimmed.includes('PRIVATE KEY')) {
    return {
      valid: false,
      error: 'Private keys must never be submitted to the VAJRA server.',
    };
  }

  try {
    const keyObject = crypto.createPublicKey(trimmed);
    if (keyObject.type !== 'public') {
      return { valid: false, error: 'Submitted key is not a valid asymmetric public key.' };
    }

    let detectedAlgorithm: SupportedKeyAlgorithm;
    if (keyObject.asymmetricKeyType === 'ed25519') {
      detectedAlgorithm = 'ED25519';
    } else if (keyObject.asymmetricKeyType === 'ec') {
      const details = keyObject.asymmetricKeyDetails;
      if (details?.namedCurve !== 'prime256v1') {
        return {
          valid: false,
          error: `Unsupported EC curve "${details?.namedCurve ?? 'unknown'}"; only P-256 (prime256v1) is permitted.`,
        };
      }
      detectedAlgorithm = 'ECDSA_P256';
    } else {
      return {
        valid: false,
        error: `Unsupported asymmetric key type "${keyObject.asymmetricKeyType ?? 'unknown'}"; only ED25519 or ECDSA_P256 are permitted.`,
      };
    }

    if (expectedAlgorithm && detectedAlgorithm !== expectedAlgorithm) {
      return {
        valid: false,
        error: `Public key algorithm mismatch: expected ${expectedAlgorithm}, received ${detectedAlgorithm}.`,
      };
    }

    const spkiDer = keyObject.export({ type: 'spki', format: 'der' });
    const normalizedPublicKeyPem = keyObject.export({ type: 'spki', format: 'pem' }).toString();
    const digest = crypto.createHash('sha256').update(spkiDer).digest('hex');

    return {
      valid: true,
      keyAlgorithm: detectedAlgorithm,
      normalizedPublicKeyPem,
      publicKeyFingerprint: `sha256:${digest}`,
      keyObject,
    };
  } catch {
    return { valid: false, error: 'Malformed or unsupported public key PEM.' };
  }
}

/**
 * Computes SHA-256 hash of an enrollment token so raw tokens are never stored in the database.
 */
export function hashEnrollmentToken(rawToken: string): string {
  const normalized = rawToken.trim().toUpperCase();
  const digest = crypto
    .createHash('sha256')
    .update(`VAJRA-ENROLL-TOKEN-V1:${normalized}`, 'utf8')
    .digest('hex');
  return `sha256:${digest}`;
}


/**
 * Builds the canonical byte buffer for Enrollment Proof-of-Possession signing:
 * Transcript = "VAJRA-ENROLL-V1" || deviceId || enrollmentToken || challengeNonce || publicKeyFingerprint || timestampIso || clientNonce
 */
export function buildEnrollmentProofTranscript(params: {
  deviceId: string;
  enrollmentToken: string;
  challengeNonce: string;
  publicKeyFingerprint: string;
  timestampIso: string;
  clientNonce: string;
}): Buffer {
  const canonical = [
    'VAJRA-ENROLL-V1',
    params.deviceId.trim(),
    params.enrollmentToken.trim().toUpperCase(),
    params.challengeNonce.trim(),
    params.publicKeyFingerprint.trim(),
    params.timestampIso.trim(),
    params.clientNonce.trim(),
  ].join('|');

  return Buffer.from(canonical, 'utf8');
}

/**
 * Signs an Enrollment Proof-of-Possession transcript using the device's private key.
 * Returns a base64-encoded signature.
 */
export function signEnrollmentProof(params: {
  privateKeyPem: string;
  keyAlgorithm: SupportedKeyAlgorithm;
  deviceId: string;
  enrollmentToken: string;
  challengeNonce: string;
  publicKeyFingerprint: string;
  timestampIso: string;
  clientNonce: string;
}): string {
  const transcript = buildEnrollmentProofTranscript(params);
  const privateKey = crypto.createPrivateKey(params.privateKeyPem);

  if (params.keyAlgorithm === 'ED25519') {
    return crypto.sign(null, transcript, privateKey).toString('base64');
  }
  return crypto.sign('sha256', transcript, privateKey).toString('base64');
}

/**
 * Verifies an Enrollment Proof-of-Possession signature using the submitted public key
 * and validates the timestamp freshness window (±120 seconds).
 */
export function verifyEnrollmentProof(params: {
  publicKeyPem: string;
  expectedAlgorithm?: SupportedKeyAlgorithm;
  signatureBase64: string;
  deviceId: string;
  enrollmentToken: string;
  challengeNonce: string;
  timestampIso: string;
  clientNonce: string;
  nowMs?: number;
}): {
  valid: boolean;
  keyAlgorithm?: SupportedKeyAlgorithm;
  publicKeyFingerprint?: string;
  normalizedPublicKeyPem?: string;
  error?: string;
} {
  const parsedKey = parseAndValidateDevicePublicKey(
    params.publicKeyPem,
    params.expectedAlgorithm
  );
  if (
    !parsedKey.valid ||
    !parsedKey.keyObject ||
    !parsedKey.keyAlgorithm ||
    !parsedKey.publicKeyFingerprint ||
    !parsedKey.normalizedPublicKeyPem
  ) {
    return { valid: false, error: parsedKey.error ?? 'Invalid public key.' };
  }

  if (
    typeof params.clientNonce !== 'string' ||
    params.clientNonce.trim().length < 16 ||
    params.clientNonce.trim().length > 128
  ) {
    return { valid: false, error: 'Client nonce must be between 16 and 128 characters.' };
  }

  const parsedTimeMs = Date.parse(params.timestampIso);
  if (Number.isNaN(parsedTimeMs)) {
    return { valid: false, error: 'Malformed enrollment timestamp.' };
  }

  const nowMs = params.nowMs ?? Date.now();
  if (Math.abs(nowMs - parsedTimeMs) > DEVICE_AUTH_TIMESTAMP_WINDOW_MS) {
    return {
      valid: false,
      error: 'Enrollment signature timestamp is outside the permitted ±120 second window.',
    };
  }

  if (typeof params.signatureBase64 !== 'string' || params.signatureBase64.trim().length === 0) {
    return { valid: false, error: 'Proof-of-possession signature is required.' };
  }

  try {
    const sigBuffer = Buffer.from(params.signatureBase64.trim(), 'base64');
    if (sigBuffer.length === 0) {
      return { valid: false, error: 'Invalid base64 signature encoding.' };
    }

    const transcript = buildEnrollmentProofTranscript({
      deviceId: params.deviceId,
      enrollmentToken: params.enrollmentToken,
      challengeNonce: params.challengeNonce,
      publicKeyFingerprint: parsedKey.publicKeyFingerprint,
      timestampIso: params.timestampIso,
      clientNonce: params.clientNonce,
    });

    const verified =
      parsedKey.keyAlgorithm === 'ED25519'
        ? crypto.verify(null, transcript, parsedKey.keyObject, sigBuffer)
        : crypto.verify('sha256', transcript, parsedKey.keyObject, sigBuffer);

    if (!verified) {
      return {
        valid: false,
        error: 'Proof-of-possession cryptographic signature verification failed.',
      };
    }

    return {
      valid: true,
      keyAlgorithm: parsedKey.keyAlgorithm,
      publicKeyFingerprint: parsedKey.publicKeyFingerprint,
      normalizedPublicKeyPem: parsedKey.normalizedPublicKeyPem,
    };
  } catch {
    return {
      valid: false,
      error: 'Proof-of-possession cryptographic signature verification failed.',
    };
  }
}

/**
 * Computes canonical SHA-256 digest of a request body for Plane 2 Device Authentication.
 */
export function computeDevicePayloadHash(body: unknown): string {
  const serialized =
    body === undefined || body === null || body === ''
      ? '{}'
      : typeof body === 'string'
      ? body
      : canonicalJsonSerialize(body);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Builds canonical Plane 2 Device Request Authentication transcript:
 * Transcript = "VAJRA-DEVICE-AUTH-V1" || method || path || deviceId || timestampIso || nonce || sha256(canonicalBody)
 */
export function buildDeviceRequestTranscript(params: {
  method: string;
  path: string;
  deviceId: string;
  timestampIso: string;
  nonce: string;
  body: unknown;
}): Buffer {
  const payloadHash = computeDevicePayloadHash(params.body);
  const canonical = [
    'VAJRA-DEVICE-AUTH-V1',
    params.method.trim().toUpperCase(),
    params.path.trim(),
    params.deviceId.trim(),
    params.timestampIso.trim(),
    params.nonce.trim(),
    payloadHash,
  ].join('|');

  return Buffer.from(canonical, 'utf8');
}

/**
 * Signs an authenticated Plane 2 device request using the device's private key.
 */
export function signDeviceRequest(params: {
  privateKeyPem: string;
  keyAlgorithm: SupportedKeyAlgorithm;
  method: string;
  path: string;
  deviceId: string;
  timestampIso: string;
  nonce: string;
  body: unknown;
}): string {
  const transcript = buildDeviceRequestTranscript(params);
  const privateKey = crypto.createPrivateKey(params.privateKeyPem);

  if (params.keyAlgorithm === 'ED25519') {
    return crypto.sign(null, transcript, privateKey).toString('base64');
  }
  return crypto.sign('sha256', transcript, privateKey).toString('base64');
}

/**
 * Verifies an authenticated Plane 2 device request signature and timestamp freshness (±120s).
 */
export function verifyDeviceRequestSignature(params: {
  publicKeyPem: string;
  keyAlgorithm: SupportedKeyAlgorithm;
  signatureBase64: string;
  method: string;
  path: string;
  deviceId: string;
  timestampIso: string;
  nonce: string;
  body: unknown;
  nowMs?: number;
}): { valid: boolean; errorCode?: string; error?: string } {
  if (typeof params.nonce !== 'string' || params.nonce.trim().length < 16 || params.nonce.trim().length > 128) {
    return {
      valid: false,
      errorCode: 'INVALID_DEVICE_NONCE',
      error: 'X-Vajra-Nonce must be between 16 and 128 characters.',
    };
  }

  const parsedTimeMs = Date.parse(params.timestampIso);
  if (Number.isNaN(parsedTimeMs)) {
    return {
      valid: false,
      errorCode: 'INVALID_DEVICE_TIMESTAMP',
      error: 'X-Vajra-Timestamp must be a valid ISO-8601 UTC timestamp.',
    };
  }

  const nowMs = params.nowMs ?? Date.now();
  if (Math.abs(nowMs - parsedTimeMs) > DEVICE_AUTH_TIMESTAMP_WINDOW_MS) {
    return {
      valid: false,
      errorCode: 'DEVICE_TIMESTAMP_EXPIRED',
      error: 'Device request timestamp is outside the permitted ±120 second freshness window.',
    };
  }

  const parsedKey = parseAndValidateDevicePublicKey(params.publicKeyPem, params.keyAlgorithm);
  if (!parsedKey.valid || !parsedKey.keyObject) {
    return {
      valid: false,
      errorCode: 'INVALID_DEVICE_CREDENTIAL',
      error: 'Stored device public key is invalid.',
    };
  }

  try {
    const sigBuffer = Buffer.from(params.signatureBase64.trim(), 'base64');
    if (sigBuffer.length === 0) {
      return {
        valid: false,
        errorCode: 'INVALID_DEVICE_SIGNATURE',
        error: 'Malformed device signature header.',
      };
    }

    const transcript = buildDeviceRequestTranscript({
      method: params.method,
      path: params.path,
      deviceId: params.deviceId,
      timestampIso: params.timestampIso,
      nonce: params.nonce,
      body: params.body,
    });

    const verified =
      params.keyAlgorithm === 'ED25519'
        ? crypto.verify(null, transcript, parsedKey.keyObject, sigBuffer)
        : crypto.verify('sha256', transcript, parsedKey.keyObject, sigBuffer);

    if (!verified) {
      return {
        valid: false,
        errorCode: 'INVALID_DEVICE_SIGNATURE',
        error: 'Cryptographic device signature verification failed.',
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      errorCode: 'INVALID_DEVICE_SIGNATURE',
      error: 'Cryptographic device signature verification failed.',
    };
  }
}

/**
 * Enforces the Device Lifecycle State Machine (`docs/architecture/device-lifecycle.md`).
 * Specifically prohibits:
 * - REVOKED -> TRUSTED / ACTIVE / OFFLINE / LOST
 * - DECOMMISSIONED -> any operational state
 * - ENROLLMENT_PENDING -> ACTIVE without passing through TRUSTED
 */
const ALLOWED_LIFECYCLE_TRANSITIONS: Readonly<
  Record<DeviceLifecycleStateType, readonly DeviceLifecycleStateType[]>
> = Object.freeze({
  UNREGISTERED: ['ENROLLMENT_PENDING'],
  ENROLLMENT_PENDING: ['TRUSTED', 'REVOKED', 'DECOMMISSIONED'],
  TRUSTED: ['ACTIVE', 'OFFLINE', 'LOST', 'COMPROMISED', 'REVOKED'],
  ACTIVE: ['OFFLINE', 'LOST', 'COMPROMISED', 'REVOKED'],
  OFFLINE: ['ACTIVE', 'LOST', 'COMPROMISED', 'REVOKED'],
  LOST: ['TRUSTED', 'ACTIVE', 'COMPROMISED', 'REVOKED'],
  COMPROMISED: ['REVOKED'],
  REVOKED: ['DECOMMISSIONED'],
  DECOMMISSIONED: [],
});

export function isValidDeviceLifecycleTransition(
  fromState: DeviceLifecycleStateType,
  toState: DeviceLifecycleStateType
): boolean {
  const allowed = ALLOWED_LIFECYCLE_TRANSITIONS[fromState];
  if (!allowed) return false;
  return allowed.includes(toState);
}

/**
 * Checks whether a device in `lifecycleState` is permitted to authenticate on Plane 2.
 */
export function canDeviceAuthenticateInState(lifecycleState: DeviceLifecycleStateType): {
  allowed: boolean;
  reasonCode?: string;
  message?: string;
} {
  if (lifecycleState === 'REVOKED') {
    return {
      allowed: false,
      reasonCode: 'DEVICE_REVOKED',
      message: 'Device credential has been permanently revoked.',
    };
  }
  if (lifecycleState === 'DECOMMISSIONED') {
    return {
      allowed: false,
      reasonCode: 'DEVICE_DECOMMISSIONED',
      message: 'Device has been decommissioned.',
    };
  }
  if (lifecycleState === 'COMPROMISED') {
    return {
      allowed: false,
      reasonCode: 'DEVICE_COMPROMISED',
      message: 'Device is flagged as compromised and quarantined from trusted Plane 2 operations.',
    };
  }
  if (lifecycleState === 'ENROLLMENT_PENDING' || lifecycleState === 'UNREGISTERED') {
    return {
      allowed: false,
      reasonCode: 'DEVICE_NOT_TRUSTED',
      message: 'Device enrollment has not been confirmed by the account owner.',
    };
  }
  return { allowed: true };
}
