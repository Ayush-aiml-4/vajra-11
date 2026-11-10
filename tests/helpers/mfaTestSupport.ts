/**
 * Test-only MFA helpers. Uses deterministic high-entropy keys that are NOT production secrets.
 */
import {
  generateTotpSecret,
  encryptTotpSecret,
  generateTotpCodeAtTime,
} from '../../packages/security/src/node.ts';
import type { InMemoryIdentityRepository } from '../../src/server/db/repository.ts';

export const TEST_TOTP_ENCRYPTION_KEY =
  'vajra-test-totp-encryption-key-32b-min!!';

export async function enableMfaForUser(
  repo: InMemoryIdentityRepository,
  userId: string,
  encryptionKeyMaterial: string = TEST_TOTP_ENCRYPTION_KEY
): Promise<string> {
  const secretBase32 = generateTotpSecret();
  const encrypted = encryptTotpSecret({
    secretBase32,
    userId,
    encryptionKeyMaterial,
  });
  await repo.updateUserCredential({
    userId,
    totpSecretEncrypted: encrypted,
    totpEnabled: true,
  });
  return secretBase32;
}

export function currentTotpCode(secretBase32: string): string {
  return generateTotpCodeAtTime(secretBase32);
}

export async function postStepUp(params: {
  baseUrl: string;
  cookie: string;
  csrfToken: string;
  totpSecretBase32: string;
  actionScope: string;
  fetchImpl?: typeof fetch;
}): Promise<Response> {
  const fetchFn = params.fetchImpl ?? fetch;
  const totpCode = currentTotpCode(params.totpSecretBase32);
  return fetchFn(`${params.baseUrl}/api/auth/step-up`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: params.cookie,
      'X-CSRF-Token': params.csrfToken,
    },
    body: JSON.stringify({
      totpCode,
      actionScope: params.actionScope,
    }),
  });
}
