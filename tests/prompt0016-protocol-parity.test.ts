/**
 * Prompt 0016 — Protocol parity tests (Node security package as source of truth).
 * Does not require live PostgreSQL or physical agents.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateDeviceKeyPair,
  buildDeviceRequestTranscript,
  buildEnrollmentProofTranscript,
  signDeviceRequest,
  verifyDeviceRequestSignature,
  signEnrollmentProof,
  verifyEnrollmentProof,
  computeDevicePayloadHash,
} from '../packages/security/src/device-identity.ts';
import { canonicalJsonSerialize } from '../packages/security/src/audit-chain.ts';

describe('Prompt 0016 — canonical body hash', () => {
  it('hashes empty body as canonical {}', () => {
    assert.equal(computeDevicePayloadHash(undefined), computeDevicePayloadHash({}));
    assert.equal(computeDevicePayloadHash(null), computeDevicePayloadHash('{}'));
    // Cross-language fixed vector (Windows/Android body hash of "{}")
    assert.equal(
      computeDevicePayloadHash({}),
      '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
    );
  });

  it('key order does not change canonical hash of equivalent objects', () => {
    const a = { connectivityStatus: 'ONLINE', agentVersion: '0.1.0', platform: 'WINDOWS' };
    const b = { platform: 'WINDOWS', agentVersion: '0.1.0', connectivityStatus: 'ONLINE' };
    assert.equal(computeDevicePayloadHash(a), computeDevicePayloadHash(b));
    assert.equal(canonicalJsonSerialize(a), canonicalJsonSerialize(b));
  });
});

describe('Prompt 0016 — ECDSA_P256 plane-2 round trip', () => {
  it('signs and verifies device request with ECDSA_P256', () => {
    const kp = generateDeviceKeyPair('ECDSA_P256');
    const body = { connectivityStatus: 'ONLINE', agentVersion: '0.1.0-windows' };
    const timestampIso = new Date().toISOString();
    const nonce = 'a'.repeat(32);
    const path = '/api/devices/00000000-0000-4000-8000-000000000001/heartbeat';

    const signatureBase64 = signDeviceRequest({
      privateKeyPem: kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path,
      deviceId: '00000000-0000-4000-8000-000000000001',
      timestampIso,
      nonce,
      body,
    });

    const result = verifyDeviceRequestSignature({
      publicKeyPem: kp.publicKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      signatureBase64,
      method: 'POST',
      path,
      deviceId: '00000000-0000-4000-8000-000000000001',
      timestampIso,
      nonce,
      body,
    });
    assert.equal(result.valid, true, result.error);

    // Tampered body fails
    const bad = verifyDeviceRequestSignature({
      publicKeyPem: kp.publicKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      signatureBase64,
      method: 'POST',
      path,
      deviceId: '00000000-0000-4000-8000-000000000001',
      timestampIso,
      nonce,
      body: { ...body, agentVersion: 'tampered' },
    });
    assert.equal(bad.valid, false);
  });

  it('rejects stale timestamps outside ±120s', () => {
    const kp = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const nonce = 'b'.repeat(32);
    const path = '/api/devices/dev/heartbeat';
    const signatureBase64 = signDeviceRequest({
      privateKeyPem: kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path,
      deviceId: 'dev',
      timestampIso,
      nonce,
      body: {},
    });
    const result = verifyDeviceRequestSignature({
      publicKeyPem: kp.publicKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      signatureBase64,
      method: 'POST',
      path,
      deviceId: 'dev',
      timestampIso,
      nonce,
      body: {},
    });
    assert.equal(result.valid, false);
    assert.equal(result.errorCode, 'DEVICE_TIMESTAMP_EXPIRED');
  });
});

describe('Prompt 0016 — enrollment PoP transcript', () => {
  it('uppercases token in enrollment transcript', () => {
    const transcript = buildEnrollmentProofTranscript({
      deviceId: 'd1',
      enrollmentToken: 'ab12',
      challengeNonce: 'c1',
      publicKeyFingerprint: 'sha256:abc',
      timestampIso: '2026-01-01T00:00:00.000Z',
      clientNonce: 'n1n1n1n1n1n1n1n1',
    });
    assert.ok(transcript.includes('|AB12|'));
    assert.ok(!transcript.includes('|ab12|'));
  });

  it('enrollment PoP signs and verifies for ECDSA_P256', () => {
    const kp = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date().toISOString();
    const clientNonce = 'c'.repeat(32);
    const params = {
      deviceId: 'd1',
      enrollmentToken: 'TOKEN99',
      challengeNonce: 'challengehex',
      publicKeyFingerprint: kp.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    };
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      ...params,
    });
    const verified = verifyEnrollmentProof({
      publicKeyPem: kp.publicKeyPem,
      expectedAlgorithm: 'ECDSA_P256',
      signatureBase64,
      deviceId: params.deviceId,
      enrollmentToken: params.enrollmentToken,
      challengeNonce: params.challengeNonce,
      timestampIso: params.timestampIso,
      clientNonce: params.clientNonce,
    });
    assert.equal(verified.valid, true, verified.error);
  });
});

describe('Prompt 0016 — transcript path stability', () => {
  it('includes method path deviceId in fixed positions', () => {
    const buf = buildDeviceRequestTranscript({
      method: 'get',
      path: '/api/devices/x/commands/pending',
      deviceId: 'x',
      timestampIso: 't',
      nonce: 'n'.repeat(16),
      body: null,
    });
    const text = buf.toString('utf8');
    const parts = text.split('|');
    assert.equal(parts[0], 'VAJRA-DEVICE-AUTH-V1');
    assert.equal(parts[1], 'GET');
    assert.equal(parts[2], '/api/devices/x/commands/pending');
    assert.equal(parts[3], 'x');
  });
});
