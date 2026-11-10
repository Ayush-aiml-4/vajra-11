/**
 * @vajra/security — Single-Use MFA Recovery Codes
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Security Rules:
 * - Generates multiple high-entropy recovery codes (default 8 codes, 80 bits entropy each)
 * - Plaintext codes are returned ONLY once at generation time
 * - Only salted SHA-256 cryptographic hashes are stored in UserCredential
 * - Each recovery code is strictly single-use (`usedAt` marked upon consumption)
 * - Verification uses constant-time comparison (`crypto.timingSafeEqual`)
 */

import crypto from 'node:crypto';

export interface StoredRecoveryCodeRecord {
  id: string;
  saltHex: string;
  codeHashHex: string;
  usedAt: string | null;
}

export interface GeneratedRecoveryCodesBundle {
  plaintextCodes: string[];
  storedRecords: StoredRecoveryCodeRecord[];
}

const RECOVERY_CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Unambiguous uppercase alphanumeric

/**
 * Normalizes user-entered recovery codes by stripping hyphens/spaces and uppercasing.
 */
export function normalizeRecoveryCode(input: string): string {
  return input.replace(/[\s-]+/g, '').toUpperCase();
}

function hashNormalizedCode(normalizedCode: string, saltHex: string): string {
  return crypto
    .createHmac('sha256', Buffer.from(saltHex, 'hex'))
    .update(`vajra-recovery-v1:${normalizedCode}`, 'utf8')
    .digest('hex');
}

/**
 * Generates `count` (default 8) high-entropy recovery codes formatted as `XXXX-XXXX-XXXX`.
 */
export function generateRecoveryCodes(count = 8): GeneratedRecoveryCodesBundle {
  const plaintextCodes: string[] = [];
  const storedRecords: StoredRecoveryCodeRecord[] = [];

  for (let i = 0; i < count; i++) {
    const randomBytes = crypto.randomBytes(12);
    let chars = '';
    for (let j = 0; j < 12; j++) {
      chars += RECOVERY_CODE_ALPHABET[randomBytes[j] % RECOVERY_CODE_ALPHABET.length];
    }

    const formatted = `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
    const normalized = normalizeRecoveryCode(formatted);
    const saltHex = crypto.randomBytes(16).toString('hex');
    const codeHashHex = hashNormalizedCode(normalized, saltHex);

    plaintextCodes.push(formatted);
    storedRecords.push({
      id: crypto.randomUUID(),
      saltHex,
      codeHashHex,
      usedAt: null,
    });
  }

  return { plaintextCodes, storedRecords };
}

/**
 * Verifies a candidate recovery code against the stored hash records.
 * If valid and unused, returns `valid: true` along with an updated array marking that code as used.
 */
export function verifyAndConsumeRecoveryCode(
  candidateCode: string,
  records: readonly StoredRecoveryCodeRecord[],
  nowIso: string = new Date().toISOString()
): {
  valid: boolean;
  consumedCodeId?: string;
  updatedRecords: StoredRecoveryCodeRecord[];
} {
  if (typeof candidateCode !== 'string' || candidateCode.trim().length < 8) {
    return { valid: false, updatedRecords: [...records] };
  }

  const normalized = normalizeRecoveryCode(candidateCode);
  if (!/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12}$/.test(normalized)) {
    return { valid: false, updatedRecords: [...records] };
  }

  let matchedIndex = -1;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (rec.usedAt !== null) {
      continue;
    }

    const candidateHashHex = hashNormalizedCode(normalized, rec.saltHex);
    const expectedBuf = Buffer.from(rec.codeHashHex, 'hex');
    const candidateBuf = Buffer.from(candidateHashHex, 'hex');

    if (
      expectedBuf.length === candidateBuf.length &&
      crypto.timingSafeEqual(expectedBuf, candidateBuf)
    ) {
      matchedIndex = i;
      break;
    }
  }

  if (matchedIndex === -1) {
    return { valid: false, updatedRecords: [...records] };
  }

  const updatedRecords = records.map((rec, idx) =>
    idx === matchedIndex ? { ...rec, usedAt: nowIso } : { ...rec }
  );

  return {
    valid: true,
    consumedCodeId: records[matchedIndex].id,
    updatedRecords,
  };
}
