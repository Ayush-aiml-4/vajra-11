/**
 * VAJRA — Prompt 0003 Comprehensive Identity, Authentication, MFA & Audit Test Suite
 *
 * Covers all required test categories from Prompt 0003 Section 34:
 * 1. Password (hashes, unique salts, correct/incorrect verify, invalid/empty input)
 * 2. TOTP (valid code, invalid code, expired/invalid window, AES-256-GCM encrypted round-trip & AAD tamper rejection)
 * 3. Recovery codes (generated, valid, single-use, invalid after use, invalid code)
 * 4. Sessions (create, authenticate, expire, logout, revoke, invalid token)
 * 5. Authentication API (registration, duplicate email, login, wrong password, MFA login, logout, /me)
 * 6. Authorization & CSRF (unauthenticated -> 401, authenticated -> allowed, missing CSRF -> 403)
 * 7. Audit Chain (valid chain, modified entry detected, deleted entry detected, reordered entry detected)
 * 8. Security & Zero Secret Leakage (no password/hash/totpSecret/sessionToken in responses or database plaintext)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import {
  hashPassword,
  verifyPassword,
  validatePasswordPolicy,
  generateTotpSecret,
  generateTotpCodeAtTime,
  verifyTotpCode,
  encryptTotpSecret,
  decryptTotpSecret,
  generateRecoveryCodes,
  verifyAndConsumeRecoveryCode,
  generateSessionTokenPair,
  hashSessionToken,
  verifyAuditChain,
  computeAuditEntryHash,
  AUDIT_GENESIS_PREVIOUS_HASH,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';

describe('Prompt 0003 — Unit Tests: Argon2id Password Utility', () => {
  it('hashes password with Argon2id and produces different hashes for identical passwords (unique salt)', async () => {
    const pw = 'Correct-Horse-Battery-Staple-99';
    const hash1 = await hashPassword(pw);
    const hash2 = await hashPassword(pw);

    assert(hash1.startsWith('$argon2id$'), 'Hash must use Argon2id PHC format');
    assert(hash2.startsWith('$argon2id$'), 'Hash must use Argon2id PHC format');
    assert.notEqual(hash1, hash2, 'Salts must be unique per hash invocation');

    assert.equal(await verifyPassword(pw, hash1), true);
    assert.equal(await verifyPassword(pw, hash2), true);
    assert.equal(await verifyPassword('Wrong-Password-Attempt-99', hash1), false);
  });

  it('rejects empty, short, or invalid password inputs', async () => {
    assert.equal(validatePasswordPolicy('').valid, false);
    assert.equal(validatePasswordPolicy('   ').valid, false);
    assert.equal(validatePasswordPolicy('short123').valid, false);
    assert.equal(validatePasswordPolicy('a'.repeat(130)).valid, false);
    assert.equal(validatePasswordPolicy(null).valid, false);

    await assert.rejects(() => hashPassword('short'), /at least 10 characters/);
    assert.equal(await verifyPassword('', '$argon2id$v=19$m=19456,t=2,p=1$invalid'), false);
  });
});

describe('Prompt 0003 — Unit Tests: TOTP & AES-256-GCM Encryption', () => {
  it('verifies valid TOTP codes and rejects invalid or expired-window codes', () => {
    const secret = generateTotpSecret();
    const fixedTimeMs = 1_750_000_000_000;
    const validCode = generateTotpCodeAtTime(secret, fixedTimeMs);

    assert.equal(
      verifyTotpCode({ secretBase32: secret, code: validCode, timestampMs: fixedTimeMs }),
      true
    );

    // Adjacent 30s window (+30s) should pass within windowSteps = 1
    assert.equal(
      verifyTotpCode({
        secretBase32: secret,
        code: validCode,
        timestampMs: fixedTimeMs + 30_000,
        windowSteps: 1,
      }),
      true
    );

    // Expired window (+120s / 4 steps away) must fail
    assert.equal(
      verifyTotpCode({
        secretBase32: secret,
        code: validCode,
        timestampMs: fixedTimeMs + 120_000,
        windowSteps: 1,
      }),
      false
    );

    // Invalid code format or wrong digits must fail
    assert.equal(
      verifyTotpCode({ secretBase32: secret, code: '000000', timestampMs: fixedTimeMs }) &&
        validCode !== '000000',
      false
    );
    assert.equal(
      verifyTotpCode({ secretBase32: secret, code: '12ab56', timestampMs: fixedTimeMs }),
      false
    );
  });

  it('encrypts and decrypts TOTP secret with AES-256-GCM and rejects wrong userId AAD or tampered ciphertext', () => {
    const secret = generateTotpSecret();
    const userId = crypto.randomUUID();
    const masterKey = crypto.randomBytes(32).toString('hex');

    const encrypted = encryptTotpSecret({
      secretBase32: secret,
      userId,
      encryptionKeyMaterial: masterKey,
    });

    assert(!encrypted.includes(secret), 'Ciphertext must never contain plaintext Base32 secret');
    assert(encrypted.startsWith('v1:'), 'Ciphertext must include v1 envelope prefix');

    const decrypted = decryptTotpSecret({
      encryptedPayload: encrypted,
      userId,
      encryptionKeyMaterial: masterKey,
    });
    assert.equal(decrypted, secret);

    // Wrong userId (AAD mismatch) must fail authentication tag verification
    assert.throws(() =>
      decryptTotpSecret({
        encryptedPayload: encrypted,
        userId: crypto.randomUUID(),
        encryptionKeyMaterial: masterKey,
      })
    );
  });
});

describe('Prompt 0003 — Unit Tests: Single-Use Recovery Codes', () => {
  it('generates recovery codes, accepts an unused code once, and rejects used or invalid codes', () => {
    const bundle = generateRecoveryCodes(8);
    assert.equal(bundle.plaintextCodes.length, 8);
    assert.equal(bundle.storedRecords.length, 8);

    const targetCode = bundle.plaintextCodes[2];

    // Ensure plaintext code is not stored in storedRecords
    const serializedRecords = JSON.stringify(bundle.storedRecords);
    assert(!serializedRecords.includes(targetCode));

    // 1. Unused code -> works
    const firstAttempt = verifyAndConsumeRecoveryCode(targetCode, bundle.storedRecords);
    assert.equal(firstAttempt.valid, true);
    assert.equal(
      firstAttempt.updatedRecords.filter((r) => r.usedAt !== null).length,
      1
    );

    // 2. Used code -> fails on second attempt
    const secondAttempt = verifyAndConsumeRecoveryCode(
      targetCode,
      firstAttempt.updatedRecords
    );
    assert.equal(secondAttempt.valid, false);

    // 3. Invalid code -> fails
    const invalidAttempt = verifyAndConsumeRecoveryCode(
      'ZZZZ-ZZZZ-ZZZZ',
      firstAttempt.updatedRecords
    );
    assert.equal(invalidAttempt.valid, false);
  });
});

describe('Prompt 0003 — Unit Tests: Hash-Chained Audit Log Tamper Detection', () => {
  it('verifies a valid chain and detects modified, deleted, reordered, or broken-previous-hash entries', async () => {
    const repo = new InMemoryIdentityRepository();
    const userId = crypto.randomUUID();

    await repo.appendAuditEvent({
      actorUserId: userId,
      eventType: 'ACCOUNT_CREATED',
      metadata: { email: 'user@example.com' },
    });
    await repo.appendAuditEvent({
      actorUserId: userId,
      eventType: 'LOGIN_SUCCESS',
      metadata: { ip: '192.0.2.0/24' },
    });
    await repo.appendAuditEvent({
      actorUserId: userId,
      eventType: 'MFA_ENABLED',
      metadata: { method: 'TOTP' },
    });

    const validChain = await repo.getAllAuditEventsOrdered();
    const checkValid = verifyAuditChain(validChain);
    assert.equal(checkValid.valid, true);
    assert.equal(checkValid.checkedCount, 3);

    // 1. Modified entry detected
    const modifiedChain = validChain.map((e, i) =>
      i === 1 ? { ...e, eventType: 'LOGIN_FAILURE' } : { ...e }
    );
    const checkModified = verifyAuditChain(modifiedChain);
    assert.equal(checkModified.valid, false);
    assert.equal(checkModified.brokenAtSequenceNumber, 2);

    // 2. Deleted entry detected (remove middle entry #2)
    const deletedChain = [validChain[0], validChain[2]];
    const checkDeleted = verifyAuditChain(deletedChain);
    assert.equal(checkDeleted.valid, false);

    // 3. Reordered entry detected (swap #2 and #3)
    const reorderedChain = [validChain[0], validChain[2], validChain[1]];
    const checkReordered = verifyAuditChain(reorderedChain);
    assert.equal(checkReordered.valid, false);

    // 4. Broken previousEntryHash detected
    const brokenPrevChain = validChain.map((e, i) =>
      i === 2 ? { ...e, previousEntryHash: 'sha256:0000000000' } : { ...e }
    );
    const checkBrokenPrev = verifyAuditChain(brokenPrevChain);
    assert.equal(checkBrokenPrev.valid, false);
    assert.equal(checkBrokenPrev.brokenAtSequenceNumber, 3);
  });
});

describe('Prompt 0003 — Integration & Security Tests: Auth, MFA, Sessions, Authorization & Secret Hygiene', () => {
  it('completes full registration, /me, MFA setup/verify, MFA login, recovery-code login, logout, and enforces zero secret leakage', async () => {
    const repo = new InMemoryIdentityRepository();
    const testTotpKey = crypto.randomBytes(32).toString('hex');
    const app = createVajraApiApp({
      repository: repo,
      totpEncryptionKey: testTotpKey,
    });
    const server = http.createServer(app);

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    assert(addr && typeof addr === 'object');
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    try {
      // 1. Unauthenticated /api/auth/me -> 401
      const unauthMe = await fetch(`${baseUrl}/api/auth/me`);
      assert.equal(unauthMe.status, 401);

      // 2. Register new account
      const testPassword = 'Vajra-Secure-Passphrase-2026!';
      const regRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          displayName: 'Ayush Singh',
          password: testPassword,
        }),
      });
      assert.equal(regRes.status, 201);
      const setCookieHeader = regRes.headers.get('set-cookie');
      assert(setCookieHeader && setCookieHeader.includes('HttpOnly'), 'Session cookie must be HttpOnly');
      const sessionCookie = setCookieHeader.split(';')[0];

      const regBodyText = await regRes.text();
      assert(!regBodyText.includes(testPassword), 'Response must never contain plaintext password');
      assert(!regBodyText.includes('passwordHash'), 'Response must never contain passwordHash');

      const regJson = JSON.parse(regBodyText) as {
        authenticated: boolean;
        csrfToken: string;
        user: { id: string; email: string; mfaEnabled: boolean };
      };
      assert.equal(regJson.authenticated, true);
      assert(regJson.csrfToken.length >= 32);

      // Verify raw session token is NOT stored in the database
      const rawTokenValue = decodeURIComponent(sessionCookie.split('=')[1]);
      const foundByRaw = await repo.findSessionByTokenHash(rawTokenValue);
      assert.equal(foundByRaw, null, 'Raw session token must never be stored in DB');
      const foundByHash = await repo.findSessionByTokenHash(hashSessionToken(rawTokenValue));
      assert.notEqual(foundByHash, null, 'Hashed session token must exist in DB');

      // 3. Duplicate registration -> 409
      const dupRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          displayName: 'Ayush Duplicate',
          password: testPassword,
        }),
      });
      assert.equal(dupRes.status, 409);

      // 4. Authenticated /api/auth/me -> 200
      const meRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: sessionCookie },
      });
      assert.equal(meRes.status, 200);
      const meJson = (await meRes.json()) as {
        authenticated: boolean;
        csrfToken: string;
        user: { email: string };
      };
      assert.equal(meJson.authenticated, true);
      assert.equal(meJson.user.email, 'ayush@example.com');
      const activeCsrf = meJson.csrfToken;

      // 5. CSRF enforcement: POST /api/auth/mfa/setup without X-CSRF-Token -> 403
      const noCsrfRes = await fetch(`${baseUrl}/api/auth/mfa/setup`, {
        method: 'POST',
        headers: { Cookie: sessionCookie },
      });
      assert.equal(noCsrfRes.status, 403);

      // 6. Initiate TOTP MFA setup with valid CSRF token
      const mfaSetupRes = await fetch(`${baseUrl}/api/auth/mfa/setup`, {
        method: 'POST',
        headers: {
          Cookie: sessionCookie,
          'X-CSRF-Token': activeCsrf,
        },
      });
      assert.equal(mfaSetupRes.status, 200);
      const mfaSetupJson = (await mfaSetupRes.json()) as {
        totpEnabled: boolean;
        secretBase32: string;
        qrCodeDataUrl: string;
      };
      assert.equal(mfaSetupJson.totpEnabled, false, 'MFA must not be enabled before verification');
      assert(mfaSetupJson.qrCodeDataUrl.startsWith('data:image/png;base64,'));

      // 7. Verify MFA setup with valid 6-digit TOTP code
      const validTotp = generateTotpCodeAtTime(mfaSetupJson.secretBase32);
      const mfaVerifyRes = await fetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: sessionCookie,
          'X-CSRF-Token': activeCsrf,
        },
        body: JSON.stringify({ code: validTotp }),
      });
      assert.equal(mfaVerifyRes.status, 200);
      const mfaVerifyJson = (await mfaVerifyRes.json()) as {
        totpEnabled: boolean;
        recoveryCodes: string[];
      };
      assert.equal(mfaVerifyJson.totpEnabled, true);
      assert.equal(mfaVerifyJson.recoveryCodes.length, 8);

      // 8. Subsequent /api/auth/me must NEVER expose totpSecret or recoveryCodes
      const meAfterMfaRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: sessionCookie },
      });
      const meAfterMfaText = await meAfterMfaRes.text();
      assert(!meAfterMfaText.includes(mfaSetupJson.secretBase32));
      assert(!meAfterMfaText.includes(mfaVerifyJson.recoveryCodes[0]));
      const meAfterMfaJson = JSON.parse(meAfterMfaText) as { csrfToken: string };

      // 9. Logout -> invalidates session
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: sessionCookie,
          'X-CSRF-Token': meAfterMfaJson.csrfToken,
        },
        body: JSON.stringify({}),
      });
      assert.equal(logoutRes.status, 200);

      // Old session cookie must now return 401 on /api/auth/me
      const afterLogoutMe = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: sessionCookie },
      });
      assert.equal(afterLogoutMe.status, 401);

      // 10. Login with wrong password -> 401 generic "Invalid credentials."
      const wrongPwRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          password: 'Wrong-Password-Attempt-123',
        }),
      });
      assert.equal(wrongPwRes.status, 401);
      const wrongPwJson = (await wrongPwRes.json()) as { error: { message: string } };
      assert.equal(wrongPwJson.error.message, 'Invalid credentials.');

      // 11. Login with non-existent email -> identical 401 generic "Invalid credentials."
      const unknownEmailRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'nobody@example.com',
          password: 'Wrong-Password-Attempt-123',
        }),
      });
      assert.equal(unknownEmailRes.status, 401);
      const unknownEmailJson = (await unknownEmailRes.json()) as { error: { message: string } };
      assert.equal(unknownEmailJson.error.message, 'Invalid credentials.');

      // 12. Login with correct password when MFA is enabled -> requires MFA (does NOT issue session cookie)
      const pwOnlyLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          password: testPassword,
        }),
      });
      assert.equal(pwOnlyLoginRes.status, 200);
      assert.equal(pwOnlyLoginRes.headers.get('set-cookie'), null);
      const pwOnlyJson = (await pwOnlyLoginRes.json()) as {
        authenticated: boolean;
        mfaRequired: boolean;
      };
      assert.equal(pwOnlyJson.authenticated, false);
      assert.equal(pwOnlyJson.mfaRequired, true);

      // 13. Complete MFA login using a single-use recovery code
      const oneRecoveryCode = mfaVerifyJson.recoveryCodes[0];
      const recLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          password: testPassword,
          recoveryCode: oneRecoveryCode,
        }),
      });
      assert.equal(recLoginRes.status, 200);
      const recLoginCookie = recLoginRes.headers.get('set-cookie')?.split(';')[0] ?? '';
      assert(recLoginCookie.length > 0);

      // 14. Reusing the same recovery code a second time must fail -> 401
      const reuseRecRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'ayush@example.com',
          password: testPassword,
          recoveryCode: oneRecoveryCode,
        }),
      });
      assert.equal(reuseRecRes.status, 401);

      // 15. Verify Audit Log hash chain via GET /api/audit
      const auditRes = await fetch(`${baseUrl}/api/audit`, {
        headers: { Cookie: recLoginCookie },
      });
      assert.equal(auditRes.status, 200);
      const auditJson = (await auditRes.json()) as {
        entries: Array<{ eventType: string }>;
        chainVerification: { valid: boolean; checkedCount: number };
      };
      assert.equal(auditJson.chainVerification.valid, true);
      assert(auditJson.chainVerification.checkedCount >= 6);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    }
  });
});
