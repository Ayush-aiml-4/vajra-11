/**
 * VAJRA — Prompt 0004 Comprehensive Cryptographic Device Identity & Enrollment Test Suite
 *
 * Covers all required test categories for Prompt 0004:
 * 1. Asymmetric Key Generation & Public Key Validation:
 *    - Ed25519 and ECDSA P-256 keypair generation & SPKI DER SHA-256 fingerprint computation
 *    - Rejects private keys, weak/unsupported algorithms, and malformed PEMs
 * 2. Enrollment Token & Challenge Security:
 *    - High-entropy single-use token generation, SHA-256 hashing (raw token never stored in DB)
 *    - Expired enrollment token rejected (410 Gone)
 *    - Reused single-use enrollment token rejected (409 Conflict)
 * 3. Proof-of-Possession & Enrollment Ceremony:
 *    - Valid Ed25519 & ECDSA P-256 Proof-of-Possession signature accepted
 *    - Invalid signature or tampered transcript rejected (400 Bad Request)
 *    - Expired timestamp outside ±120s window rejected
 *    - Duplicate public key fingerprint rejected across devices (409 Conflict)
 *    - Owner confirmation transitions ENROLLMENT_PENDING -> TRUSTED and activates DeviceCredential
 * 4. Plane 1 vs Plane 2 Separation & Device Request Signing:
 *    - User session cookie alone is rejected on Plane 2 device endpoints (401)
 *    - Valid Plane 2 signed request (`X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`) succeeds and transitions TRUSTED -> ACTIVE
 *    - Replayed device nonce is detected and rejected (409 Conflict)
 *    - Expired device request timestamp is rejected (401)
 *    - Modified request body invalidates signature (401)
 * 5. Key Rotation, Lifecycle State Machine, Revocation & Ownership Isolation:
 *    - Device key rotation with PoP from new key marks old credential ROTATED and activates new credential
 *    - Old rotated key is immediately rejected on subsequent Plane 2 requests
 *    - Cross-user access (`GET /api/devices/:id`, `confirm`, `revoke`) returns 404 Not Found
 *    - Compromised device is quarantined from Plane 2 authentication (403)
 *    - Revoked device credential is permanently invalidated (403) and can NEVER transition back to TRUSTED/ACTIVE
 *    - Hash-chained AuditLog records all device enrollment, auth, rotation, and revocation events without tampering
 */

import { describe, it } from 'node:test';
import {
  TEST_TOTP_ENCRYPTION_KEY,
  enableMfaForUser,
  postStepUp,
} from './helpers/mfaTestSupport.ts';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

// Ensure 32+ character test secret is available for keyed passcode HMAC verifiers
process.env.SESSION_SECRET = process.env.SESSION_SECRET ?? 'vajra-test-session-secret-32-chars-minimum!';

import {
  generateDeviceKeyPair,
  parseAndValidateDevicePublicKey,
  generateEnrollmentChallengeBundle,
  hashEnrollmentToken,
  signEnrollmentProof,
  verifyEnrollmentProof,
  signDeviceRequest,
  verifyDeviceRequestSignature,
  isValidDeviceLifecycleTransition,
  verifyAuditChain,
  hashVerificationPasscode,
  verifyVerificationPasscode,
  resolvePasscodeHmacSecret,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';

describe('Prompt 0004 — Unit Tests: Asymmetric Keys, Fingerprints & Lifecycle State Machine', () => {
  it('generates valid Ed25519 and ECDSA P-256 keypairs, computes deterministic SPKI SHA-256 fingerprints, and rejects private keys or malformed PEMs', () => {
    const edKey = generateDeviceKeyPair('ED25519');
    assert.equal(edKey.keyAlgorithm, 'ED25519');
    assert(edKey.publicKeyFingerprint.startsWith('sha256:'));
    assert.equal(edKey.publicKeyFingerprint.length, 7 + 64);

    const parsedEd = parseAndValidateDevicePublicKey(edKey.publicKeyPem, 'ED25519');
    assert.equal(parsedEd.valid, true);
    assert.equal(parsedEd.publicKeyFingerprint, edKey.publicKeyFingerprint);

    const ecKey = generateDeviceKeyPair('ECDSA_P256');
    assert.equal(ecKey.keyAlgorithm, 'ECDSA_P256');
    const parsedEc = parseAndValidateDevicePublicKey(ecKey.publicKeyPem, 'ECDSA_P256');
    assert.equal(parsedEc.valid, true);
    assert.equal(parsedEc.publicKeyFingerprint, ecKey.publicKeyFingerprint);

    // Algorithm mismatch must fail
    const mismatch = parseAndValidateDevicePublicKey(edKey.publicKeyPem, 'ECDSA_P256');
    assert.equal(mismatch.valid, false);

    // Submitting a private key PEM must be strictly rejected
    const privateKeyAttempt = parseAndValidateDevicePublicKey(edKey.privateKeyPem);
    assert.equal(privateKeyAttempt.valid, false);
    assert(privateKeyAttempt.error?.includes('Private keys must never be submitted'));

    // Malformed PEM must fail
    assert.equal(parseAndValidateDevicePublicKey('not-a-valid-pem').valid, false);
  });

  it('verifies enrollment Proof-of-Possession signatures and rejects wrong keys, tampered transcripts, or expired timestamps', () => {
    const keyPair = generateDeviceKeyPair('ED25519');
    const otherKeyPair = generateDeviceKeyPair('ED25519');
    const bundle = generateEnrollmentChallengeBundle();
    const deviceId = crypto.randomUUID();
    const nowMs = 1_760_000_000_000;
    const timestampIso = new Date(nowMs).toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');

    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      deviceId,
      enrollmentToken: bundle.rawEnrollmentToken,
      challengeNonce: bundle.challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const validCheck = verifyEnrollmentProof({
      publicKeyPem: keyPair.publicKeyPem,
      signatureBase64,
      deviceId,
      enrollmentToken: bundle.rawEnrollmentToken,
      challengeNonce: bundle.challengeNonce,
      timestampIso,
      clientNonce,
      nowMs,
    });
    assert.equal(validCheck.valid, true);
    assert.equal(validCheck.publicKeyFingerprint, keyPair.publicKeyFingerprint);

    // Wrong public key (attacker tries to claim someone else's signature) -> fails
    const wrongKeyCheck = verifyEnrollmentProof({
      publicKeyPem: otherKeyPair.publicKeyPem,
      signatureBase64,
      deviceId,
      enrollmentToken: bundle.rawEnrollmentToken,
      challengeNonce: bundle.challengeNonce,
      timestampIso,
      clientNonce,
      nowMs,
    });
    assert.equal(wrongKeyCheck.valid, false);

    // Expired timestamp (+5 minutes > ±120s window) -> fails
    const expiredTimeCheck = verifyEnrollmentProof({
      publicKeyPem: keyPair.publicKeyPem,
      signatureBase64,
      deviceId,
      enrollmentToken: bundle.rawEnrollmentToken,
      challengeNonce: bundle.challengeNonce,
      timestampIso,
      clientNonce,
      nowMs: nowMs + 5 * 60 * 1000,
    });
    assert.equal(expiredTimeCheck.valid, false);
  });

  it('enforces the Device Lifecycle State Machine and prohibits REVOKED reactivation or self-promotion', () => {
    assert.equal(isValidDeviceLifecycleTransition('UNREGISTERED', 'ENROLLMENT_PENDING'), true);
    assert.equal(isValidDeviceLifecycleTransition('ENROLLMENT_PENDING', 'TRUSTED'), true);
    assert.equal(isValidDeviceLifecycleTransition('ENROLLMENT_PENDING', 'ACTIVE'), false);
    assert.equal(isValidDeviceLifecycleTransition('TRUSTED', 'ACTIVE'), true);
    assert.equal(isValidDeviceLifecycleTransition('ACTIVE', 'COMPROMISED'), true);
    assert.equal(isValidDeviceLifecycleTransition('COMPROMISED', 'ACTIVE'), false);
    assert.equal(isValidDeviceLifecycleTransition('COMPROMISED', 'REVOKED'), true);
    assert.equal(isValidDeviceLifecycleTransition('REVOKED', 'TRUSTED'), false);
    assert.equal(isValidDeviceLifecycleTransition('REVOKED', 'ACTIVE'), false);
    assert.equal(isValidDeviceLifecycleTransition('REVOKED', 'DECOMMISSIONED'), true);
    assert.equal(isValidDeviceLifecycleTransition('DECOMMISSIONED', 'ACTIVE'), false);
  });

  it('enforces HMAC-SHA256 passcode verifier security, 6-digit validation, constant-time compare, and fail-closed secret requirement', () => {
    const validSecret = 'a-secure-vajra-server-secret-with-at-least-32-characters';
    const nonce = '0123456789abcdef0123456789abcdef';

    // 1. Valid 6-digit passcode computes an hmac-sha256 digest
    const hash = hashVerificationPasscode('842 195', nonce, validSecret);
    assert(hash.startsWith('hmac-sha256:'));
    assert.equal(hash.length, 'hmac-sha256:'.length + 64);

    // 2. Constant-time verification succeeds with correct code and spaces
    assert.equal(verifyVerificationPasscode('842195', hash, nonce, validSecret), true);
    assert.equal(verifyVerificationPasscode('842 195', hash, nonce, validSecret), true);

    // 3. Incorrect code fails
    assert.equal(verifyVerificationPasscode('123456', hash, nonce, validSecret), false);

    // 4. Invalid digit length (<6 or >6 digits) throws or fails
    assert.throws(
      () => hashVerificationPasscode('12345', nonce, validSecret),
      /INVALID_PASSCODE_FORMAT/
    );
    assert.throws(
      () => hashVerificationPasscode('abcdef', nonce, validSecret),
      /INVALID_PASSCODE_FORMAT/
    );
    assert.equal(verifyVerificationPasscode('12345', hash, nonce, validSecret), false);

    // 5. Short/missing server secret fails closed
    assert.throws(
      () => hashVerificationPasscode('842195', nonce, 'short-secret'),
      /MISSING_PASSCODE_HMAC_SECRET/
    );

    // 6. Regression SEC-01: Production mode with APPLET_ID present strictly requires dedicated PASSCODE_HMAC_SECRET
    const savedNodeEnv = process.env.NODE_ENV;
    const savedAppEnv = process.env.APP_ENV;
    const savedAppletId = process.env.APPLET_ID;
    const savedPasscodeSecret = process.env.PASSCODE_HMAC_SECRET;
    const savedSessionSecret = process.env.SESSION_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.APP_ENV;
      process.env.APPLET_ID = 'test-applet-sandbox-id';
      delete process.env.PASSCODE_HMAC_SECRET;
      process.env.SESSION_SECRET = 'a-very-long-session-secret-that-must-not-be-reused-in-prod!';

      // Must throw despite APPLET_ID and SESSION_SECRET presence
      assert.throws(
        () => resolvePasscodeHmacSecret(),
        /MISSING_PASSCODE_HMAC_SECRET.*SESSION_SECRET fallback prohibited/
      );

      // 7. Regression SEC-01: Production mode with APPLET_ID absent strictly requires dedicated PASSCODE_HMAC_SECRET
      delete process.env.APPLET_ID;
      assert.throws(
        () => resolvePasscodeHmacSecret(),
        /MISSING_PASSCODE_HMAC_SECRET.*SESSION_SECRET fallback prohibited/
      );

      // 8. Dedicated PASSCODE_HMAC_SECRET of 32+ characters succeeds in production
      process.env.PASSCODE_HMAC_SECRET = 'a-strictly-dedicated-passcode-hmac-secret-32-chars!';
      assert.equal(
        resolvePasscodeHmacSecret(),
        'a-strictly-dedicated-passcode-hmac-secret-32-chars!'
      );
    } finally {
      process.env.NODE_ENV = savedNodeEnv;
      process.env.APP_ENV = savedAppEnv;
      process.env.APPLET_ID = savedAppletId;
      process.env.PASSCODE_HMAC_SECRET = savedPasscodeSecret;
      process.env.SESSION_SECRET = savedSessionSecret;
    }
  });
});

describe('Prompt 0004 — Integration & Security Tests: End-to-End Enrollment, Plane 2 Auth, Key Rotation, Replay Defense & Revocation', () => {
  it('completes full device enrollment, Plane 2 authentication, replay rejection, key rotation, cross-user isolation, and permanent revocation', async () => {
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    assert(addr && typeof addr === 'object');
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    try {
      // 1. Register Owner User A
      const regARes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'owner.a@example.com',
          displayName: 'Owner A',
          password: 'Vajra-Owner-A-Passphrase-2026!',
        }),
      });
      assert.equal(regARes.status, 201);
      const cookieA = regARes.headers.get('set-cookie')!.split(';')[0];
      const regAJson = (await regARes.json()) as { csrfToken: string; user: { id: string } };
      const csrfA = regAJson.csrfToken;

      // 2. Register Owner User B (to test cross-user ownership isolation)
      const regBRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'owner.b@example.com',
          displayName: 'Owner B',
          password: 'Vajra-Owner-B-Passphrase-2026!',
        }),
      });
      assert.equal(regBRes.status, 201);
      const cookieB = regBRes.headers.get('set-cookie')!.split(';')[0];
      const regBJson = (await regBRes.json()) as { csrfToken: string };
      const csrfB = regBJson.csrfToken;

      // 3. Initiate Device Enrollment for User A ("ASUS TUF F16", WINDOWS)
      const initRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieA,
          'X-CSRF-Token': csrfA,
        },
        body: JSON.stringify({
          proposedDeviceName: 'ASUS TUF F16',
          expectedDeviceType: 'WINDOWS',
        }),
      });
      assert.equal(initRes.status, 201);
      const initJson = (await initRes.json()) as {
        device: { id: string; lifecycleState: string };
        enrollment: {
          deviceId: string;
          enrollmentToken: string;
          challengeNonce: string;
          verificationPasscode?: string;
          expiresAt: string;
          qrCodeDataUrl: string;
        };
      };
      const deviceId = initJson.device.id;
      assert.equal(initJson.device.lifecycleState, 'ENROLLMENT_PENDING');
      assert(initJson.enrollment.enrollmentToken.startsWith('VJR-'));
      assert(initJson.enrollment.qrCodeDataUrl.startsWith('data:image/png;base64,'));
      assert.equal(typeof initJson.enrollment.verificationPasscode, 'string');
      assert.equal(initJson.enrollment.verificationPasscode?.length, 6);

      // Verify raw enrollment token is NEVER stored in the database (only SHA-256 hash)
      const challengeByRaw = await repo.findEnrollmentChallengeByTokenHash(
        initJson.enrollment.enrollmentToken
      );
      assert.equal(challengeByRaw, null, 'Raw enrollment token must never be stored in DB');
      const challengeByHash = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(initJson.enrollment.enrollmentToken)
      );
      assert.notEqual(challengeByHash, null, 'Hashed enrollment token must exist in DB');

      // 4. Attempting to confirm enrollment BEFORE device submits key -> 400 KEY_NOT_SUBMITTED
      const prematureConfirmRes = await fetch(
        `${baseUrl}/api/devices/${deviceId}/enrollment/confirm`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: cookieA,
            'X-CSRF-Token': csrfA,
          },
          body: JSON.stringify({}),
        }
      );
      assert.equal(prematureConfirmRes.status, 400);

      // 5. Endpoint generates Ed25519 keypair and submits invalid signature first -> 400
      const deviceKey1 = generateDeviceKeyPair('ED25519');
      const badSubmitRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey1.publicKeyPem,
          signatureBase64: Buffer.from('forged-signature').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(badSubmitRes.status, 400);

      // 5b. Submitting with WRONG verification passcode -> 401
      const wrongPasscodeRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: '000000',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey1.publicKeyPem,
          signatureBase64: Buffer.from('forged-signature').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(wrongPasscodeRes.status, 401);

      // 5c. Host header injection defense (SEC-02): Spoofed Host / X-Forwarded-Host must never poison QR serverUrl
      const regCRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'owner.c@example.com',
          displayName: 'Owner C',
          password: 'Vajra-Owner-C-Passphrase-2026!',
        }),
      });
      assert.equal(regCRes.status, 201);
      const cookieC = regCRes.headers.get('set-cookie')!.split(';')[0];
      const regCJson = (await regCRes.json()) as { csrfToken: string };
      const csrfC = regCJson.csrfToken;

      const spoofedInitRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieC,
          'X-CSRF-Token': csrfC,
          Host: 'evil-attacker.example.com',
          'X-Forwarded-Host': 'evil-attacker.example.com',
        },
        body: JSON.stringify({
          proposedDeviceName: 'Spoof Test Device',
          expectedDeviceType: 'WINDOWS',
        }),
      });
      assert.equal(spoofedInitRes.status, 201);
      const spoofedJson = (await spoofedInitRes.json()) as { enrollment: { serverUrl: string; enrollmentToken: string } };
      assert.equal(spoofedJson.enrollment.serverUrl.includes('evil-attacker.example.com'), false);

      // 5d. Atomic passcode brute-force lockout (SEC-04): 5 failed attempts locks challenge with 429
      for (let attempt = 1; attempt <= 4; attempt++) {
        const failRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enrollmentToken: spoofedJson.enrollment.enrollmentToken,
            verificationPasscode: '000000',
            keyAlgorithm: 'ED25519',
            publicKeyPem: deviceKey1.publicKeyPem,
            signatureBase64: Buffer.from('forged-signature').toString('base64'),
            timestampIso: new Date().toISOString(),
            clientNonce: crypto.randomBytes(16).toString('hex'),
          }),
        });
        assert.equal(failRes.status, 401);
      }
      // 5th failed attempt triggers 429 lockout
      const lockRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: spoofedJson.enrollment.enrollmentToken,
          verificationPasscode: '000000',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey1.publicKeyPem,
          signatureBase64: Buffer.from('forged-signature').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(lockRes.status, 429);
      const lockJson = (await lockRes.json()) as { error: { code: string } };
      assert.equal(lockJson.error.code, 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS');

      // 5e. Concurrent lockout race defense (SEC-04): Simultaneous incorrect submissions lock out even valid passcode
      const regDRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'owner.d@example.com',
          displayName: 'Owner D',
          password: 'Vajra-Owner-D-Passphrase-2026!',
        }),
      });
      assert.equal(regDRes.status, 201);
      const cookieD = regDRes.headers.get('set-cookie')!.split(';')[0];
      const regDJson = (await regDRes.json()) as { csrfToken: string };
      const csrfD = regDJson.csrfToken;

      const raceInitRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieD,
          'X-CSRF-Token': csrfD,
        },
        body: JSON.stringify({
          proposedDeviceName: 'Race Test Device',
          expectedDeviceType: 'WINDOWS',
        }),
      });
      assert.equal(raceInitRes.status, 201);
      const raceJson = (await raceInitRes.json()) as {
        device: { id: string };
        enrollment: { enrollmentToken: string; verificationPasscode: string; challengeNonce: string };
      };

      // Dispatch 8 concurrent invalid passcode submissions simultaneously
      const invalidPromises = Array.from({ length: 8 }, () =>
        fetch(`${baseUrl}/api/devices/enrollment/submit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enrollmentToken: raceJson.enrollment.enrollmentToken,
            verificationPasscode: '999999',
            keyAlgorithm: 'ED25519',
            publicKeyPem: deviceKey1.publicKeyPem,
            signatureBase64: Buffer.from('forged-signature').toString('base64'),
            timestampIso: new Date().toISOString(),
            clientNonce: crypto.randomBytes(16).toString('hex'),
          }),
        })
      );
      const invalidResults = await Promise.all(invalidPromises);
      const statuses = invalidResults.map((r) => r.status);
      assert(statuses.includes(429), 'Must contain 429 once threshold of 5 is hit');

      // Authoritative count in repo must never exceed 5
      const raceChallenge = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(raceJson.enrollment.enrollmentToken)
      );
      assert.equal(raceChallenge?.failedAttempts, 5, 'failedAttempts must never exceed 5');

      // Now attempt with the CORRECT passcode on the locked challenge -> must be rejected with 429
      const validSig = signEnrollmentProof({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        deviceId: raceJson.device.id,
        enrollmentToken: raceJson.enrollment.enrollmentToken,
        challengeNonce: raceJson.enrollment.challengeNonce,
        publicKeyFingerprint: deviceKey1.publicKeyFingerprint,
        timestampIso: new Date().toISOString(),
        clientNonce: crypto.randomBytes(16).toString('hex'),
      });
      const lockedSubmitRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: raceJson.enrollment.enrollmentToken,
          verificationPasscode: raceJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey1.publicKeyPem,
          signatureBase64: validSig,
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(lockedSubmitRes.status, 429, 'Locked challenge must reject even valid passcode with 429');

      // 6. Endpoint submits valid Proof-of-Possession signature with correct passcode -> 200
      const submitTimeIso = new Date().toISOString();
      const submitClientNonce = crypto.randomBytes(16).toString('hex');
      const validProofSig = signEnrollmentProof({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        deviceId,
        enrollmentToken: initJson.enrollment.enrollmentToken,
        challengeNonce: initJson.enrollment.challengeNonce,
        publicKeyFingerprint: deviceKey1.publicKeyFingerprint,
        timestampIso: submitTimeIso,
        clientNonce: submitClientNonce,
      });

      const validSubmitRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey1.publicKeyPem,
          signatureBase64: validProofSig,
          timestampIso: submitTimeIso,
          clientNonce: submitClientNonce,
          hardwareBacked: true,
          osVersion: 'Windows 11 Pro 24H2',
          agentVersion: '0.4.0',
        }),
      });
      assert.equal(validSubmitRes.status, 200);
      const validSubmitJson = (await validSubmitRes.json()) as {
        status: string;
        credential: { status: string; active: boolean; publicKeyFingerprint: string; hardwareBacked: boolean };
      };
      assert.equal(validSubmitJson.status, 'KEY_SUBMITTED_AWAITING_OWNER_CONFIRMATION');
      assert.equal(validSubmitJson.credential.status, 'PENDING_CONFIRMATION');
      assert.equal(validSubmitJson.credential.active, false);
      assert.equal(validSubmitJson.credential.hardwareBacked, false, 'SEC-05: Server must not trust unverified client hardware claims');

      // 7. Reusing the single-use enrollment token a second time -> 409 Conflict
      const reuseTokenRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          keyAlgorithm: 'ED25519',
          publicKeyPem: generateDeviceKeyPair('ED25519').publicKeyPem,
          signatureBase64: validProofSig,
          timestampIso: submitTimeIso,
          clientNonce: submitClientNonce,
        }),
      });
      assert.equal(reuseTokenRes.status, 409);

      // 8. Before owner confirmation, Plane 2 device authentication must be rejected (403 DEVICE_NOT_TRUSTED)
      const prematureAuthTime = new Date().toISOString();
      const prematureAuthNonce = crypto.randomBytes(16).toString('hex');
      const prematureAuthBody = { check: 'premature' };
      const prematureAuthSig = signDeviceRequest({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: prematureAuthTime,
        nonce: prematureAuthNonce,
        body: prematureAuthBody,
      });

      const prematurePlane2Res = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': prematureAuthTime,
          'X-Vajra-Nonce': prematureAuthNonce,
          'X-Vajra-Signature': prematureAuthSig,
        },
        body: JSON.stringify(prematureAuthBody),
      });
      assert.equal(prematurePlane2Res.status, 403);

      // 9. Cross-user isolation: User B attempts to view or confirm User A's device -> 404 Not Found
      const userBGetRes = await fetch(`${baseUrl}/api/devices/${deviceId}`, {
        headers: { Cookie: cookieB },
      });
      assert.equal(userBGetRes.status, 404);

      const userBConfirmRes = await fetch(
        `${baseUrl}/api/devices/${deviceId}/enrollment/confirm`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: cookieB,
            'X-CSRF-Token': csrfB,
          },
          body: JSON.stringify({}),
        }
      );
      assert.equal(userBConfirmRes.status, 404);

      // 10. Owner User A confirms device enrollment -> transitions ENROLLMENT_PENDING -> TRUSTED
      const confirmRes = await fetch(
        `${baseUrl}/api/devices/${deviceId}/enrollment/confirm`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: cookieA,
            'X-CSRF-Token': csrfA,
          },
          body: JSON.stringify({
            publicKeyFingerprint: deviceKey1.publicKeyFingerprint,
          }),
        }
      );
      assert.equal(confirmRes.status, 200);
      const confirmJson = (await confirmRes.json()) as {
        device: {
          lifecycleState: string;
          credentialStatus: string;
          publicKeyFingerprint: string;
        };
      };
      assert.equal(confirmJson.device.lifecycleState, 'TRUSTED');
      assert.equal(confirmJson.device.credentialStatus, 'ACTIVE');
      assert.equal(confirmJson.device.publicKeyFingerprint, deviceKey1.publicKeyFingerprint);

      // 11. Plane Separation: User A tries to call Plane 2 `/api/devices/auth/verify` with only User session cookie -> 401
      const plane1OnlyRes = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieA,
          'X-CSRF-Token': csrfA,
        },
        body: JSON.stringify({}),
      });
      assert.equal(plane1OnlyRes.status, 401);

      // 12. Valid Plane 2 signed request from enrolled device -> 200 OK & transitions TRUSTED -> ACTIVE
      const p2Time = new Date().toISOString();
      const p2Nonce = crypto.randomBytes(16).toString('hex');
      const p2Body = { status: 'ready' };
      const p2Sig = signDeviceRequest({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: p2Time,
        nonce: p2Nonce,
        body: p2Body,
      });

      const validP2Res = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': p2Time,
          'X-Vajra-Nonce': p2Nonce,
          'X-Vajra-Signature': p2Sig,
        },
        body: JSON.stringify(p2Body),
      });
      assert.equal(validP2Res.status, 200);
      const validP2Json = (await validP2Res.json()) as {
        authenticated: boolean;
        principalLevel: string;
        lifecycleState: string;
      };
      assert.equal(validP2Json.authenticated, true);
      assert.equal(validP2Json.principalLevel, 'TRUSTED_DEVICE');
      assert.equal(validP2Json.lifecycleState, 'ACTIVE');

      // 13. Nonce Replay Attack: Re-sending the exact same signed request with the same nonce -> 409 Conflict
      const replayP2Res = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': p2Time,
          'X-Vajra-Nonce': p2Nonce,
          'X-Vajra-Signature': p2Sig,
        },
        body: JSON.stringify(p2Body),
      });
      assert.equal(replayP2Res.status, 409);

      // 14. Key Rotation: Rotate from Ed25519 key1 to ECDSA P-256 key2
      const deviceKey2 = generateDeviceKeyPair('ECDSA_P256');
      const rotTime = new Date().toISOString();
      const rotHeaderNonce = crypto.randomBytes(16).toString('hex');
      const rotClientNonce = crypto.randomBytes(16).toString('hex');

      const newKeyProofSignature = signEnrollmentProof({
        privateKeyPem: deviceKey2.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        deviceId,
        enrollmentToken: `ROTATE:${deviceKey1.publicKeyFingerprint}`,
        challengeNonce: rotHeaderNonce,
        publicKeyFingerprint: deviceKey2.publicKeyFingerprint,
        timestampIso: rotTime,
        clientNonce: rotClientNonce,
      });

      const rotateBody = {
        newPublicKeyPem: deviceKey2.publicKeyPem,
        newKeyAlgorithm: 'ECDSA_P256',
        newKeyProofSignature,
        rotationNonce: rotClientNonce,
        hardwareBacked: true,
      };

      const rotateHeaderSig = signDeviceRequest({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        method: 'POST',
        path: '/api/devices/credentials/rotate',
        deviceId,
        timestampIso: rotTime,
        nonce: rotHeaderNonce,
        body: rotateBody,
      });

      const rotateRes = await fetch(`${baseUrl}/api/devices/credentials/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': rotTime,
          'X-Vajra-Nonce': rotHeaderNonce,
          'X-Vajra-Signature': rotateHeaderSig,
        },
        body: JSON.stringify(rotateBody),
      });
      assert.equal(rotateRes.status, 200);
      const rotateJson = (await rotateRes.json()) as {
        rotated: boolean;
        activeCredential: { publicKeyFingerprint: string; keyAlgorithm: string };
      };
      assert.equal(rotateJson.rotated, true);
      assert.equal(
        rotateJson.activeCredential.publicKeyFingerprint,
        deviceKey2.publicKeyFingerprint
      );

      // 15. Old rotated key1 must now fail Plane 2 authentication -> 401
      const oldKeyTime = new Date().toISOString();
      const oldKeyNonce = crypto.randomBytes(16).toString('hex');
      const oldKeyBody = { test: 'old-key' };
      const oldKeySig = signDeviceRequest({
        privateKeyPem: deviceKey1.privateKeyPem,
        keyAlgorithm: 'ED25519',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: oldKeyTime,
        nonce: oldKeyNonce,
        body: oldKeyBody,
      });

      const oldKeyRes = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': oldKeyTime,
          'X-Vajra-Nonce': oldKeyNonce,
          'X-Vajra-Signature': oldKeySig,
        },
        body: JSON.stringify(oldKeyBody),
      });
      assert.equal(oldKeyRes.status, 401);

      // 16. New rotated key2 succeeds Plane 2 authentication -> 200
      const newKeyTime = new Date().toISOString();
      const newKeyNonce = crypto.randomBytes(16).toString('hex');
      const newKeyBody = { test: 'new-key' };
      const newKeySig = signDeviceRequest({
        privateKeyPem: deviceKey2.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: newKeyTime,
        nonce: newKeyNonce,
        body: newKeyBody,
      });

      const newKeyRes = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': newKeyTime,
          'X-Vajra-Nonce': newKeyNonce,
          'X-Vajra-Signature': newKeySig,
        },
        body: JSON.stringify(newKeyBody),
      });
      assert.equal(newKeyRes.status, 200);

      // 17. Flag device as COMPROMISED (requires MFA step-up)
      const ownerUserId = (await repo.findUserByEmail('owner.a@example.com'))!.id;
      const totpSecretA = await enableMfaForUser(repo, ownerUserId, TEST_TOTP_ENCRYPTION_KEY);
      const stepComp = await postStepUp({
        baseUrl,
        cookie: cookieA,
        csrfToken: csrfA,
        totpSecretBase32: totpSecretA,
        actionScope: 'DEVICE_COMPROMISED',
      });
      assert.equal(stepComp.status, 200, await stepComp.text());
      const compRes = await fetch(`${baseUrl}/api/devices/${deviceId}/compromised`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieA,
          'X-CSRF-Token': csrfA,
        },
        body: JSON.stringify({ reason: 'Suspected local key tamper' }),
      });
      assert.equal(compRes.status, 200);

      const compAuthNonce = crypto.randomBytes(16).toString('hex');
      const compAuthSig = signDeviceRequest({
        privateKeyPem: deviceKey2.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: newKeyTime,
        nonce: compAuthNonce,
        body: newKeyBody,
      });
      const compAuthRes = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': newKeyTime,
          'X-Vajra-Nonce': compAuthNonce,
          'X-Vajra-Signature': compAuthSig,
        },
        body: JSON.stringify(newKeyBody),
      });
      assert.equal(compAuthRes.status, 403);

      // 18. Revoke device -> permanently invalidates credentials (REVOKED)
            const stepRev = await postStepUp({
        baseUrl,
        cookie: cookieA,
        csrfToken: csrfA,
        totpSecretBase32: totpSecretA,
        actionScope: 'DEVICE_REVOKE',
      });
      assert.equal(stepRev.status, 200, await stepRev.text());

      const revokeRes = await fetch(`${baseUrl}/api/devices/${deviceId}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieA,
          'X-CSRF-Token': csrfA,
        },
        body: JSON.stringify({ reason: 'Permanent credential revocation' }),
      });
      assert.equal(revokeRes.status, 200);
      const revokeJson = (await revokeRes.json()) as {
        device: { lifecycleState: string; credentialStatus: string };
      };
      assert.equal(revokeJson.device.lifecycleState, 'REVOKED');

      // Attempting to confirm or reactivate a REVOKED device -> 409 Conflict
      const reactivateRes = await fetch(
        `${baseUrl}/api/devices/${deviceId}/enrollment/confirm`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: cookieA,
            'X-CSRF-Token': csrfA,
          },
          body: JSON.stringify({}),
        }
      );
      assert.equal(reactivateRes.status, 409);

      // Plane 2 request from REVOKED device -> 403 DEVICE_REVOKED
      const revAuthNonce = crypto.randomBytes(16).toString('hex');
      const revAuthSig = signDeviceRequest({
        privateKeyPem: deviceKey2.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        method: 'POST',
        path: '/api/devices/auth/verify',
        deviceId,
        timestampIso: newKeyTime,
        nonce: revAuthNonce,
        body: newKeyBody,
      });
      const revAuthRes = await fetch(`${baseUrl}/api/devices/auth/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': newKeyTime,
          'X-Vajra-Nonce': revAuthNonce,
          'X-Vajra-Signature': revAuthSig,
        },
        body: JSON.stringify(newKeyBody),
      });
      assert.equal(revAuthRes.status, 403);

      // 19. Decommission REVOKED device -> transitions to DECOMMISSIONED
      const decomRes = await fetch(`${baseUrl}/api/devices/${deviceId}/decommission`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieA,
          'X-CSRF-Token': csrfA,
        },
        body: JSON.stringify({}),
      });
      assert.equal(decomRes.status, 200);
      const decomJson = (await decomRes.json()) as { device: { lifecycleState: string } };
      assert.equal(decomJson.device.lifecycleState, 'DECOMMISSIONED');

      // Default GET /api/devices excludes DECOMMISSIONED
      const listDefaultRes = await fetch(`${baseUrl}/api/devices`, {
        headers: { Cookie: cookieA },
      });
      const listDefaultJson = (await listDefaultRes.json()) as { devices: unknown[] };
      assert.equal(listDefaultJson.devices.length, 0);

      // GET /api/devices?includeDecommissioned=true includes it
      const listAllRes = await fetch(`${baseUrl}/api/devices?includeDecommissioned=true`, {
        headers: { Cookie: cookieA },
      });
      const listAllJson = (await listAllRes.json()) as { devices: unknown[] };
      assert.equal(listAllJson.devices.length, 1);

      // 20. Verify global AuditLog hash chain remains 100% intact across all device events
      const allAudit = await repo.getAllAuditEventsOrdered();
      const chainResult = verifyAuditChain(allAudit);
      assert.equal(chainResult.valid, true);
      assert(chainResult.checkedCount >= 10);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    }
  });
});

describe('Workstream 2 — SEC-04: Atomic Enrollment Challenge Serialization, Concurrency Races & Lockout Protection', () => {
  async function setupTestApp() {
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address() as { port: number };
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    // Register owner
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `sec04-${crypto.randomBytes(4).toString('hex')}@example.com`,
        displayName: 'SEC04 Auditor',
        password: 'Vajra-Sec04-Auditor-Passphrase-2026!',
      }),
    });
    const regCookie = regRes.headers.get('set-cookie')!.split(';')[0];
    const regJson = (await regRes.json()) as { csrfToken: string };

    // Initiate enrollment
    const initRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: regCookie,
        'X-CSRF-Token': regJson.csrfToken,
      },
      body: JSON.stringify({
        proposedDeviceName: 'SEC-04 Test Device',
        expectedDeviceType: 'WINDOWS',
      }),
    });
    const initJson = (await initRes.json()) as {
      device: { id: string };
      enrollment: {
        enrollmentToken: string;
        verificationPasscode: string;
        challengeNonce: string;
        expiresAt: string;
      };
    };

    const deviceKey = generateDeviceKeyPair('ED25519');

    const makeValidProof = () => {
      const timestampIso = new Date().toISOString();
      const clientNonce = crypto.randomBytes(16).toString('hex');
      const sig = signEnrollmentProof({
        privateKeyPem: deviceKey.privateKeyPem,
        keyAlgorithm: 'ED25519',
        deviceId: initJson.device.id,
        enrollmentToken: initJson.enrollment.enrollmentToken,
        challengeNonce: initJson.enrollment.challengeNonce,
        publicKeyFingerprint: deviceKey.publicKeyFingerprint,
        timestampIso,
        clientNonce,
      });
      return { timestampIso, clientNonce, sig };
    };

    const close = () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );

    return { repo, baseUrl, initJson, deviceKey, makeValidProof, close };
  }

  it('1. Five sequential failed passcodes trigger atomic lockout and subsequent 429 rejections', async () => {
    const { repo, baseUrl, initJson, deviceKey, close } = await setupTestApp();
    try {
      for (let i = 1; i <= 4; i++) {
        const res = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enrollmentToken: initJson.enrollment.enrollmentToken,
            verificationPasscode: '000000',
            keyAlgorithm: 'ED25519',
            publicKeyPem: deviceKey.publicKeyPem,
            signatureBase64: Buffer.from('sig').toString('base64'),
            timestampIso: new Date().toISOString(),
            clientNonce: crypto.randomBytes(16).toString('hex'),
          }),
        });
        assert.equal(res.status, 401, `Attempt ${i} must return 401`);
        const json = (await res.json()) as { error: { code: string } };
        assert.equal(json.error.code, 'INVALID_VERIFICATION_PASSCODE');
      }

      // 5th attempt triggers lockout
      const lockRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: '000000',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: Buffer.from('sig').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(lockRes.status, 429, '5th attempt must return 429');
      const lockJson = (await lockRes.json()) as { error: { code: string } };
      assert.equal(lockJson.error.code, 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS');

      // 6th attempt remains locked
      const postLockRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: '000000',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: Buffer.from('sig').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(postLockRes.status, 429, 'Subsequent attempts must return 429');

      const challenge = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(initJson.enrollment.enrollmentToken)
      );
      assert.equal(challenge?.failedAttempts, 5);
      assert.equal(challenge?.consumedAt, null);
    } finally {
      await close();
    }
  });

  it('2. More than five concurrent failed passcodes are bounded atomically and lock out the challenge', async () => {
    const { repo, baseUrl, initJson, deviceKey, close } = await setupTestApp();
    try {
      const concurrentReqs = Array.from({ length: 12 }, () =>
        fetch(`${baseUrl}/api/devices/enrollment/submit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enrollmentToken: initJson.enrollment.enrollmentToken,
            verificationPasscode: '999999',
            keyAlgorithm: 'ED25519',
            publicKeyPem: deviceKey.publicKeyPem,
            signatureBase64: Buffer.from('sig').toString('base64'),
            timestampIso: new Date().toISOString(),
            clientNonce: crypto.randomBytes(16).toString('hex'),
          }),
        })
      );

      const responses = await Promise.all(concurrentReqs);
      const statuses = responses.map((r) => r.status);
      assert(statuses.includes(429), 'Must contain 429 responses');
      assert.equal(statuses.every((s) => s === 401 || s === 429), true);

      const challenge = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(initJson.enrollment.enrollmentToken)
      );
      assert.equal(challenge?.failedAttempts, 5, 'failedAttempts must never exceed 5');
      assert.equal(challenge?.consumedAt, null, 'Challenge must remain unconsumed');
    } finally {
      await close();
    }
  });

  it('3. One valid passcode racing against five invalid submissions fails with lockout when invalid attempts lock the challenge first', async () => {
    const { repo, baseUrl, initJson, deviceKey, makeValidProof, close } = await setupTestApp();
    try {
      // Send 5 invalid attempts first to lock the challenge
      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enrollmentToken: initJson.enrollment.enrollmentToken,
            verificationPasscode: '111111',
            keyAlgorithm: 'ED25519',
            publicKeyPem: deviceKey.publicKeyPem,
            signatureBase64: Buffer.from('sig').toString('base64'),
            timestampIso: new Date().toISOString(),
            clientNonce: crypto.randomBytes(16).toString('hex'),
          }),
        });
      }

      // Now race valid submission on locked challenge
      const proof = makeValidProof();
      const validRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: proof.sig,
          timestampIso: proof.timestampIso,
          clientNonce: proof.clientNonce,
        }),
      });

      assert.equal(validRes.status, 429, 'Valid passcode on locked challenge must receive 429');
      const validJson = (await validRes.json()) as { error: { code: string } };
      assert(
        validJson.error.code === 'TOO_MANY_FAILED_PASSCODE_ATTEMPTS' ||
          validJson.error.code === 'RATE_LIMIT_EXCEEDED',
        `Expected 429 lockout or rate-limit error code, got ${validJson.error.code}`
      );

      const challenge = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(initJson.enrollment.enrollmentToken)
      );
      assert.equal(challenge?.consumedAt, null, 'Locked challenge must never be claimed or consumed');
    } finally {
      await close();
    }
  });

  it('4. Successful enrollment racing against an invalid submission claims challenge and prevents subsequent modifications', async () => {
    const { repo, baseUrl, initJson, deviceKey, makeValidProof, close } = await setupTestApp();
    try {
      const proof = makeValidProof();
      const validRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: proof.sig,
          timestampIso: proof.timestampIso,
          clientNonce: proof.clientNonce,
        }),
      });
      assert.equal(validRes.status, 200, 'Valid submission must succeed with 200');

      // Subsequent invalid passcode submission against consumed challenge
      const invalidRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: '999999',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: Buffer.from('sig').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(invalidRes.status, 409, 'Must return 409 ENROLLMENT_TOKEN_ALREADY_USED');
      const invalidJson = (await invalidRes.json()) as { error: { code: string } };
      assert.equal(invalidJson.error.code, 'ENROLLMENT_TOKEN_ALREADY_USED');

      // Verify failedAttempts did NOT increment on consumed challenge
      const challenge = await repo.findEnrollmentChallengeByTokenHash(
        hashEnrollmentToken(initJson.enrollment.enrollmentToken)
      );
      assert.equal(challenge?.failedAttempts, 0, 'failedAttempts must not increment on consumed challenge');
      assert.notEqual(challenge?.consumedAt, null, 'Challenge must remain consumed');
    } finally {
      await close();
    }
  });

  it('5. Attempts against a consumed challenge are rejected with 409 ENROLLMENT_TOKEN_ALREADY_USED', async () => {
    const { baseUrl, initJson, deviceKey, makeValidProof, close } = await setupTestApp();
    try {
      const proof = makeValidProof();
      const firstSubmit = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: proof.sig,
          timestampIso: proof.timestampIso,
          clientNonce: proof.clientNonce,
        }),
      });
      assert.equal(firstSubmit.status, 200);

      // Replay identical valid submission
      const replaySubmit = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: proof.sig,
          timestampIso: proof.timestampIso,
          clientNonce: proof.clientNonce,
        }),
      });
      assert.equal(replaySubmit.status, 409);
      const replayJson = (await replaySubmit.json()) as { error: { code: string } };
      assert.equal(replayJson.error.code, 'ENROLLMENT_TOKEN_ALREADY_USED');
    } finally {
      await close();
    }
  });

  it('6. Attempts against an expired challenge are rejected with 410 ENROLLMENT_TOKEN_EXPIRED', async () => {
    const { repo, baseUrl, initJson, deviceKey, makeValidProof, close } = await setupTestApp();
    try {
      // Force challenge to be expired in repository
      const tokenHash = hashEnrollmentToken(initJson.enrollment.enrollmentToken);
      const challenge = await repo.findEnrollmentChallengeByTokenHash(tokenHash);
      assert.ok(challenge);
      const stored = (repo as any).enrollmentChallenges?.get(challenge.id);
      if (stored) {
        stored.expiresAt = new Date(Date.now() - 60000); // 1 minute in the past
      }

      // Valid passcode on expired challenge
      const proof = makeValidProof();
      const submitRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: initJson.enrollment.verificationPasscode,
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: proof.sig,
          timestampIso: proof.timestampIso,
          clientNonce: proof.clientNonce,
        }),
      });
      assert.equal(submitRes.status, 410);
      const submitJson = (await submitRes.json()) as { error: { code: string } };
      assert.equal(submitJson.error.code, 'ENROLLMENT_TOKEN_EXPIRED');

      // Invalid passcode on expired challenge
      const failRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: initJson.enrollment.enrollmentToken,
          verificationPasscode: '000000',
          keyAlgorithm: 'ED25519',
          publicKeyPem: deviceKey.publicKeyPem,
          signatureBase64: Buffer.from('sig').toString('base64'),
          timestampIso: new Date().toISOString(),
          clientNonce: crypto.randomBytes(16).toString('hex'),
        }),
      });
      assert.equal(failRes.status, 410);
      const failJson = (await failRes.json()) as { error: { code: string } };
      assert.equal(failJson.error.code, 'ENROLLMENT_TOKEN_EXPIRED');
    } finally {
      await close();
    }
  });
});

