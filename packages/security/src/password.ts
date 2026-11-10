/**
 * @vajra/security — Argon2id Password Hashing & Password Policy
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Security Rules:
 * - Never store plaintext passwords
 * - Never use SHA-256, MD5, or reversible encryption for passwords
 * - Uses Argon2id (Algorithm.Argon2id = 2) with unique 16-byte random salt per password
 * - Chosen Argon2id parameters:
 *   memoryCost = 19456 KiB (19 MiB — OWASP recommended minimum for Argon2id)
 *   timeCost   = 2 iterations
 *   parallelism = 1 lane
 *   outputLen  = 32 bytes
 * - Enforces reasonable passphrase-friendly length policy (10 to 128 characters)
 */

import { hash, verify } from '@node-rs/argon2';

// Algorithm.Argon2id === 2 in @node-rs/argon2 (defined as a numeric literal to comply with isolatedModules)
export const ARGON2ID_ALGORITHM_ID = 2 as const;

export const ARGON2ID_PARAMS = Object.freeze({
  algorithm: ARGON2ID_ALGORITHM_ID,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
});

export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 128;

export interface PasswordValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validates password policy without logging or echoing the password value.
 */
export function validatePasswordPolicy(password: unknown): PasswordValidationResult {
  if (typeof password !== 'string') {
    return { valid: false, reason: 'Password must be a valid string.' };
  }

  if (password.trim().length === 0) {
    return { valid: false, reason: 'Password cannot be empty or whitespace only.' };
  }

  if (password.length < PASSWORD_MIN_LENGTH) {
    return {
      valid: false,
      reason: `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`,
    };
  }

  if (password.length > PASSWORD_MAX_LENGTH) {
    return {
      valid: false,
      reason: `Password must not exceed ${PASSWORD_MAX_LENGTH} characters.`,
    };
  }

  if (password.includes('\u0000')) {
    return { valid: false, reason: 'Password contains invalid null characters.' };
  }

  return { valid: true };
}

/**
 * Hashes a validated plaintext password using Argon2id with a unique random salt.
 */
export async function hashPassword(password: string): Promise<string> {
  const policyCheck = validatePasswordPolicy(password);
  if (!policyCheck.valid) {
    throw new Error(policyCheck.reason ?? 'Invalid password input.');
  }

  return hash(password, {
    algorithm: ARGON2ID_PARAMS.algorithm,
    memoryCost: ARGON2ID_PARAMS.memoryCost,
    timeCost: ARGON2ID_PARAMS.timeCost,
    parallelism: ARGON2ID_PARAMS.parallelism,
    outputLen: ARGON2ID_PARAMS.outputLen,
  });
}

// Precomputed dummy Argon2id hash used to equalize timing when a user email does not exist
let cachedDummyHash: string | null = null;

export async function getDummyPasswordHash(): Promise<string> {
  if (!cachedDummyHash) {
    cachedDummyHash = await hash('vajra-dummy-timing-equalizer-passphrase', {
      algorithm: ARGON2ID_PARAMS.algorithm,
      memoryCost: ARGON2ID_PARAMS.memoryCost,
      timeCost: ARGON2ID_PARAMS.timeCost,
      parallelism: ARGON2ID_PARAMS.parallelism,
      outputLen: ARGON2ID_PARAMS.outputLen,
    });
  }
  return cachedDummyHash;
}

/**
 * Verifies a plaintext password against an Argon2id PHC string hash.
 * Never throws or leaks internal hash details on mismatch.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (
    typeof password !== 'string' ||
    password.length === 0 ||
    password.length > PASSWORD_MAX_LENGTH ||
    typeof storedHash !== 'string' ||
    !storedHash.startsWith('$argon2id$')
  ) {
    return false;
  }

  try {
    return await verify(storedHash, password);
  } catch {
    return false;
  }
}
