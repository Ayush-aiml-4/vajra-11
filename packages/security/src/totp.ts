/**
 * @vajra/security — Standards-Compliant TOTP (RFC 6238 / RFC 4226) & AES-256-GCM Secret Encryption
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Security Rules:
 * - TOTP secrets are 160-bit (20-byte) cryptographically random buffers encoded in RFC 4648 Base32
 * - TOTP secrets are NEVER stored in plaintext; they are encrypted with AES-256-GCM
 *   using a dedicated 256-bit key derived from TOTP_ENCRYPTION_KEY and bound to userId via AAD
 * - Verification uses constant-time comparison across a tight +-1 time-step window (30s step)
 */

import crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

/**
 * Encodes a Buffer into RFC 4648 Base32 (without padding '=').
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes an RFC 4648 Base32 string into a Buffer.
 */
export function base32Decode(base32Input: string): Buffer {
  const cleaned = base32Input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error('Invalid Base32 character in TOTP secret.');
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a fresh 160-bit (20-byte) cryptographic TOTP secret in Base32 format.
 */
export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * Builds a standard otpauth://totp/ URI suitable for authenticator app QR codes.
 */
export function buildTotpProvisioningUri(params: {
  secretBase32: string;
  accountEmail: string;
  issuer?: string;
}): string {
  const issuer = params.issuer ?? 'VAJRA Security';
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(params.accountEmail)}`;
  const query = new URLSearchParams({
    secret: params.secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_STEP_SECONDS),
  });

  return `otpauth://totp/${label}?${query.toString()}`;
}

/**
 * Generates the 6-digit TOTP code for a specific Unix timestamp (milliseconds).
 */
export function generateTotpCodeAtTime(
  secretBase32: string,
  timestampMs: number = Date.now()
): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / TOTP_STEP_SECONDS);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binaryCode % 10 ** TOTP_DIGITS;
  return String(otp).padStart(TOTP_DIGITS, '0');
}

/**
 * Verifies a 6-digit TOTP code using constant-time comparison across [-windowSteps, +windowSteps].
 */
export function verifyTotpCode(params: {
  secretBase32: string;
  code: string;
  timestampMs?: number;
  windowSteps?: number;
}): boolean {
  const normalizedCode = typeof params.code === 'string' ? params.code.trim() : '';
  if (!/^\d{6}$/.test(normalizedCode)) {
    return false;
  }

  const nowMs = params.timestampMs ?? Date.now();
  const windowSteps = params.windowSteps ?? 1;
  const candidateBuffer = Buffer.from(normalizedCode, 'utf8');

  for (let stepOffset = -windowSteps; stepOffset <= windowSteps; stepOffset++) {
    const stepTimeMs = nowMs + stepOffset * TOTP_STEP_SECONDS * 1000;
    const expectedCode = generateTotpCodeAtTime(params.secretBase32, stepTimeMs);
    const expectedBuffer = Buffer.from(expectedCode, 'utf8');

    if (
      candidateBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(candidateBuffer, expectedBuffer)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Derives a 32-byte (256-bit) key from the configured TOTP_ENCRYPTION_KEY master material
 * using HKDF-SHA256.
 */
function deriveAes256Key(masterKeyMaterial: string): Buffer {
  if (!masterKeyMaterial || masterKeyMaterial.trim().length < 16) {
    throw new Error('TOTP_ENCRYPTION_KEY must be at least 16 characters of high-entropy secret.');
  }
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      Buffer.from(masterKeyMaterial, 'utf8'),
      Buffer.from('vajra-totp-aes256gcm-salt-v1', 'utf8'),
      Buffer.from('vajra-totp-secret-encryption', 'utf8'),
      32
    )
  );
}

/**
 * Encrypts a Base32 TOTP secret using AES-256-GCM with a random 96-bit IV and userId AAD binding.
 * Format: v1:<iv_base64url>:<authTag_base64url>:<ciphertext_base64url>
 */
export function encryptTotpSecret(params: {
  secretBase32: string;
  userId: string;
  encryptionKeyMaterial: string;
}): string {
  const key = deriveAes256Key(params.encryptionKeyMaterial);
  const iv = crypto.randomBytes(12); // 96-bit IV recommended by NIST for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  cipher.setAAD(Buffer.from(`vajra-totp:${params.userId}`, 'utf8'));

  const encrypted = Buffer.concat([
    cipher.update(params.secretBase32, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return [
    'v1',
    iv.toString('base64url'),
    authTag.toString('base64url'),
    encrypted.toString('base64url'),
  ].join(':');
}

/**
 * Decrypts an AES-256-GCM encrypted TOTP secret and verifies the authentication tag and userId AAD.
 */
export function decryptTotpSecret(params: {
  encryptedPayload: string;
  userId: string;
  encryptionKeyMaterial: string;
}): string {
  const parts = params.encryptedPayload.split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Invalid encrypted TOTP secret envelope.');
  }

  const key = deriveAes256Key(params.encryptionKeyMaterial);
  const iv = Buffer.from(parts[1], 'base64url');
  const authTag = Buffer.from(parts[2], 'base64url');
  const ciphertext = Buffer.from(parts[3], 'base64url');

  if (iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Malformed AES-256-GCM IV or authentication tag length.');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(`vajra-totp:${params.userId}`, 'utf8'));
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}
