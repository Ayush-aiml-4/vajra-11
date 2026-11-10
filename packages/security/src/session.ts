/**
 * @vajra/security — Server-Side Session Token & Cookie Cryptographic Utilities
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Security Rules:
 * - Raw session tokens are 256-bit cryptographically random Base64URL strings
 * - Only SHA-256(token) is stored in DeviceSession (`tokenHash`)
 * - CSRF tokens are 256-bit random values paired with each session (`csrfTokenHash`)
 * - Sessions enforce both idle TTL (default 900s / 15m) and absolute lifetime (12h)
 */

import crypto from 'node:crypto';

export const SESSION_IDLE_TTL_MS = 15 * 60 * 1000; // 15 minutes
export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
export const SESSION_ROTATION_THRESHOLD_MS = 7.5 * 60 * 1000; // Rotate after 7.5 minutes

export interface GeneratedSessionTokenPair {
  rawSessionToken: string;
  sessionTokenHash: string;
  rawCsrfToken: string;
  csrfTokenHash: string;
}

/**
 * Computes the SHA-256 hex digest of a session or CSRF token.
 */
export function hashSessionToken(rawToken: string): string {
  return crypto.createHash('sha256').update(`vajra-session-v1:${rawToken}`, 'utf8').digest('hex');
}

/**
 * Generates a fresh 256-bit session token and 256-bit CSRF token along with their SHA-256 hashes.
 */
export function generateSessionTokenPair(): GeneratedSessionTokenPair {
  const rawSessionToken = crypto.randomBytes(32).toString('base64url');
  const rawCsrfToken = crypto.randomBytes(32).toString('base64url');

  return {
    rawSessionToken,
    sessionTokenHash: hashSessionToken(rawSessionToken),
    rawCsrfToken,
    csrfTokenHash: hashSessionToken(rawCsrfToken),
  };
}

/**
 * Constant-time verification of a candidate CSRF token against a stored SHA-256 hash.
 */
export function verifyCsrfToken(candidateRawToken: string, expectedTokenHashHex: string): boolean {
  if (typeof candidateRawToken !== 'string' || candidateRawToken.length < 16) {
    return false;
  }
  const candidateHashHex = hashSessionToken(candidateRawToken);
  const a = Buffer.from(candidateHashHex, 'hex');
  const b = Buffer.from(expectedTokenHashHex, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
