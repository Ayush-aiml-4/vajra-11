/**
 * @vajra/security
 * Foundational security boundaries, ethical invariants, and input sanitization utilities.
 * Browser-safe and Node-safe entry point.
 * For Node.js server cryptographic primitives (Argon2id, AES-256-GCM TOTP, Recovery Codes, Session Hashes, Audit Chain),
 * import from `@vajra/security/node` (`packages/security/src/node.ts`).
 */

export interface SecurityBoundaryPolicy {
  readonly id: string;
  readonly category: 'PROHIBITED_CAPABILITY' | 'MANDATORY_SAFEGUARD';
  readonly title: string;
  readonly description: string;
  readonly enforced: boolean;
}

export interface AuditChainEntry {
  id: string;
  sequenceNumber: number;
  actorUserId: string | null;
  eventType: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  previousEntryHash: string;
  entryHash: string;
}

export interface AuditChainVerificationResult {
  valid: boolean;
  checkedCount: number;
  brokenAtSequenceNumber?: number;
  reason?: string;
}

/**
 * Explicit list of prohibited capabilities in VAJRA.
 * VAJRA is a legitimate personal-device security product, never spyware or offensive malware.
 */
export const PROHIBITED_CAPABILITIES: readonly string[] = Object.freeze([
  'stealth_spyware',
  'keylogging',
  'password_collection',
  'credential_theft',
  'hidden_microphone_recording',
  'hidden_webcam_recording',
  'covert_screen_recording',
  'bypass_android_permissions',
  'bypass_windows_security',
  'bypass_antivirus_defender',
  'rootkits',
  'evasive_persistence',
  'privilege_escalation',
  'disable_security_software',
  'arbitrary_remote_shell_execution',
  'arbitrary_remote_code_execution',
]);

/**
 * Core architectural security principles enforced across all VAJRA modules.
 */
export const CORE_SECURITY_INVARIANTS: readonly SecurityBoundaryPolicy[] = Object.freeze([
  {
    id: 'INV-01',
    category: 'MANDATORY_SAFEGUARD',
    title: 'Separation of Authentication & Authorization',
    description:
      'User session authentication, cryptographic device identity authentication, and step-up command authorization operate as independent verification layers.',
    enforced: true,
  },
  {
    id: 'INV-02',
    category: 'MANDATORY_SAFEGUARD',
    title: 'Hardware-Backed Device Identity',
    description:
      'Private keys remain non-exportable on the host device (Windows TPM / DPAPI or Android Keystore) whenever supported; backend stores only public keys and registration metadata.',
    enforced: true,
  },
  {
    id: 'INV-03',
    category: 'MANDATORY_SAFEGUARD',
    title: 'Allowlisted Command Execution Only',
    description:
      'Remote commands are strictly constrained to an explicit enum allowlist (e.g., RING_DEVICE, REQUEST_HEARTBEAT). Arbitrary shell or code execution is structurally impossible.',
    enforced: true,
  },
  {
    id: 'INV-04',
    category: 'MANDATORY_SAFEGUARD',
    title: 'OS Permission & Boundary Respect',
    description:
      'Agents rely exclusively on documented Windows and Android APIs. When an OS restricts an action, VAJRA documents the limitation and requests user consent rather than bypassing controls.',
    enforced: true,
  },
]);

/**
 * Validates whether a requested capability is permitted under VAJRA's ethical security charter.
 */
export function isCapabilityPermitted(capabilityIdentifier: string): boolean {
  const normalized = capabilityIdentifier.trim().toLowerCase().replace(/[\s-]+/g, '_');
  return !PROHIBITED_CAPABILITIES.includes(normalized);
}

/**
 * Redacts potentially sensitive keys from structured log metadata so secrets are never logged.
 */
export function sanitizeLogMetadata(record: Record<string, unknown>): Record<string, unknown> {
  const sensitivePattern = /(password|secret|token|key|authorization|cookie|credential)/i;
  const sanitized: Record<string, unknown> = {};

  for (const [k, v] of Object.entries(record)) {
    if (sensitivePattern.test(k)) {
      sanitized[k] = '[REDACTED]';
    } else if (typeof v === 'string' && v.length > 512) {
      sanitized[k] = `${v.slice(0, 512)}...[TRUNCATED]`;
    } else {
      sanitized[k] = v;
    }
  }

  return sanitized;
}
