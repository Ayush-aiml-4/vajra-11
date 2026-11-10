/**
 * @vajra/security — Tamper-Evident Hash-Chained Audit Log & Verification
 * Prompt 0003: Identity & Authentication Foundation
 *
 * Canonical Hash Construction Specification:
 * Each AuditLog entry computes:
 *   entryHash = "sha256:" + SHA256(
 *     "VAJRA-AUDIT-V1|" +
 *     sequenceNumber + "|" +
 *     id + "|" +
 *     (actorUserId ?? "SYSTEM") + "|" +
 *     eventType + "|" +
 *     timestampIso + "|" +
 *     canonicalJson(sanitizedMetadata) + "|" +
 *     previousEntryHash
 *   )
 *
 * Genesis entry (sequenceNumber === 1) uses previousEntryHash = "GENESIS_VAJRA_AUDIT_CHAIN_V1".
 */

import crypto from 'node:crypto';
import {
  sanitizeLogMetadata,
  AuditChainEntry,
  AuditChainVerificationResult,
} from './index.ts';

export type { AuditChainEntry, AuditChainVerificationResult };

export const AUDIT_GENESIS_PREVIOUS_HASH = 'GENESIS_VAJRA_AUDIT_CHAIN_V1';

export type AuthAuditEventType =
  | 'ACCOUNT_CREATED'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'MFA_SETUP_STARTED'
  | 'MFA_ENABLED'
  | 'MFA_DISABLED'
  | 'MFA_VERIFICATION_FAILURE'
  | 'RECOVERY_CODE_USED'
  | 'RECOVERY_CODES_REGENERATED'
  | 'PASSWORD_CHANGED'
  | 'SESSION_REVOKED'
  | 'ACCOUNT_LOCKED'
  | 'DEVICE_ENROLLMENT_INITIATED'
  | 'DEVICE_KEY_SUBMITTED'
  | 'DEVICE_ENROLLMENT_PROOF_FAILURE'
  | 'DEVICE_ENROLLED'
  | 'DEVICE_KEY_ROTATED'
  | 'DEVICE_REVOKED'
  | 'DEVICE_DECOMMISSIONED'
  | 'DEVICE_COMPROMISED_FLAGGED'
  | 'DEVICE_AUTH_VERIFIED'
  | 'DEVICE_AUTH_FAILURE'
  | 'DEVICE_REPLAY_DETECTED'
  | 'LOCATION_REQUESTED'
  | 'LOCATION_UPDATED'
  | 'RING_REQUESTED'
  | 'RING_ACKNOWLEDGED'
  | 'RECOVERY_MESSAGE_REQUESTED'
  | 'RECOVERY_MESSAGE_DISPLAYED'
  | 'LOST_MODE_ENABLED'
  | 'LOST_MODE_DISABLED'
  | 'DEVICE_STATUS_REQUESTED'
  | 'THREATCHECK_COMPLETED';

/**
 * Deterministic recursive key-sorted JSON serializer for canonical hashing.
 */
export function canonicalJsonSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJsonSerialize(item)).join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort();
  const pairs = sortedKeys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJsonSerialize(record[k])}`
  );
  return `{${pairs.join(',')}}`;
}

/**
 * Computes the canonical SHA-256 entryHash for an audit log record.
 */
export function computeAuditEntryHash(params: {
  id: string;
  sequenceNumber: number;
  actorUserId: string | null;
  eventType: string;
  timestampIso: string;
  metadata: Record<string, unknown>;
  previousEntryHash: string;
}): string {
  const sanitizedMetadata = sanitizeLogMetadata(params.metadata);
  const canonicalPayload = [
    'VAJRA-AUDIT-V1',
    String(params.sequenceNumber),
    params.id,
    params.actorUserId ?? 'SYSTEM',
    params.eventType,
    params.timestampIso,
    canonicalJsonSerialize(sanitizedMetadata),
    params.previousEntryHash,
  ].join('|');

  const digest = crypto.createHash('sha256').update(canonicalPayload, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

/**
 * Verifies an ordered sequence of AuditChainEntry records for:
 * 1. Missing/deleted entries (sequenceNumber gaps)
 * 2. Reordered entries (non-monotonic sequenceNumber)
 * 3. Broken previousEntryHash links
 * 4. Modified entry fields or tampered metadata (entryHash mismatch)
 */
export function verifyAuditChain(entries: readonly AuditChainEntry[]): AuditChainVerificationResult {
  if (entries.length === 0) {
    return { valid: true, checkedCount: 0 };
  }

  for (let i = 0; i < entries.length; i++) {
    const current = entries[i];
    const expectedSequence = i + 1;

    if (current.sequenceNumber !== expectedSequence) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: current.sequenceNumber,
        reason: `Sequence number discontinuity at index ${i}: expected ${expectedSequence}, found ${current.sequenceNumber} (deleted or reordered entry).`,
      };
    }

    const expectedPrevHash =
      i === 0 ? AUDIT_GENESIS_PREVIOUS_HASH : entries[i - 1].entryHash;

    if (current.previousEntryHash !== expectedPrevHash) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: current.sequenceNumber,
        reason: `Broken previousEntryHash link at sequence ${current.sequenceNumber}.`,
      };
    }

    const recomputedHash = computeAuditEntryHash({
      id: current.id,
      sequenceNumber: current.sequenceNumber,
      actorUserId: current.actorUserId,
      eventType: current.eventType,
      timestampIso: current.timestamp,
      metadata: current.metadata,
      previousEntryHash: current.previousEntryHash,
    });

    if (current.entryHash !== recomputedHash) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: current.sequenceNumber,
        reason: `Entry hash mismatch at sequence ${current.sequenceNumber} (modified record detected).`,
      };
    }
  }

  return {
    valid: true,
    checkedCount: entries.length,
  };
}
