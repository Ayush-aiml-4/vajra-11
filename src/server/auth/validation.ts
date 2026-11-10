/**
 * VAJRA — Input Validation & Sanitization Utilities
 * Prompt 0003: Rejects malformed data before business logic without exposing internals.
 */

import { validatePasswordPolicy } from '../../../packages/security/src/node.ts';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function validateEmailInput(email: unknown): {
  valid: boolean;
  normalizedEmail?: string;
  error?: string;
} {
  if (typeof email !== 'string') {
    return { valid: false, error: 'Email is required.' };
  }
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 5 || normalized.length > 254 || !EMAIL_REGEX.test(normalized)) {
    return { valid: false, error: 'Please provide a valid email address.' };
  }
  return { valid: true, normalizedEmail: normalized };
}

export function validateDisplayNameInput(displayName: unknown): {
  valid: boolean;
  sanitizedName?: string;
  error?: string;
} {
  if (typeof displayName !== 'string') {
    return { valid: false, error: 'Display name is required.' };
  }
  const trimmed = displayName.trim().replace(/[<>]/g, '');
  if (trimmed.length < 2 || trimmed.length > 64) {
    return { valid: false, error: 'Display name must be between 2 and 64 characters.' };
  }
  return { valid: true, sanitizedName: trimmed };
}

export function validatePasswordInput(password: unknown): {
  valid: boolean;
  error?: string;
} {
  const res = validatePasswordPolicy(password);
  return { valid: res.valid, error: res.reason };
}

export function validateTotpCodeInput(code: unknown): {
  valid: boolean;
  normalizedCode?: string;
  error?: string;
} {
  if (typeof code !== 'string') {
    return { valid: false, error: 'Verification code is required.' };
  }
  const cleaned = code.trim();
  if (!/^\d{6}$/.test(cleaned)) {
    return { valid: false, error: 'Authenticator code must be a 6-digit number.' };
  }
  return { valid: true, normalizedCode: cleaned };
}

export function validateRecoveryCodeInput(code: unknown): {
  valid: boolean;
  normalizedCode?: string;
  error?: string;
} {
  if (typeof code !== 'string') {
    return { valid: false, error: 'Recovery code is required.' };
  }
  const cleaned = code.replace(/[\s-]+/g, '').toUpperCase();
  if (!/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12}$/.test(cleaned)) {
    return { valid: false, error: 'Invalid recovery code format.' };
  }
  return { valid: true, normalizedCode: cleaned };
}

export function isValidUuid(id: unknown): id is string {
  return typeof id === 'string' && UUID_REGEX.test(id);
}
