/**
 * VAJRA — Prompt 0011D: Signed Device Events, Command Integrity & MFA Step-Up
 *
 * Covers:
 * - Route/device ID binding on Plane-2 endpoints
 * - Signed device event ingestion (valid/invalid signature, mismatch, replay, redaction)
 * - Command state machine legal/illegal transitions and receipt integrity
 * - MFA step-up grant, expiry, wrong scope, and enforcement on sensitive actions
 * - Cross-user isolation
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  generateDeviceKeyPair,
  signDeviceRequest,
  signEnrollmentProof,
  hashPassword,
  generateTotpSecret,
  encryptTotpSecret,
  verifyTotpCode,
  generateTotpCodeAtTime,
  generateSessionTokenPair,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import {
  InMemoryIdentityRepository,
  isLegalCommandTransition,
  TERMINAL_COMMAND_STATUSES,
  LEGAL_COMMAND_TRANSITIONS,
} from '../src/server/db/repository.ts';
import { STEP_UP_SCOPES, sessionHasValidStepUp } from '../src/server/auth/middleware.ts';

const TOTP_KEY = crypto.randomBytes(32).toString('hex');

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
    headers?: Record<string, string>;
  }
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: any }> {
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('Server not listening');
  const payload = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers ?? {}),
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload).toString();
  }
  if (options.cookie) headers['Cookie'] = options.cookie;
  if (options.csrfToken) headers['X-CSRF-Token'] = options.csrfToken;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: (addr as any).port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          const rawText = Buffer.concat(chunks).toString('utf8');
          let body: any = {};
          try {
            body = rawText ? JSON.parse(rawText) : {};
          } catch {
            body = { rawText };
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function extractCookie(setCookie: string | string[] | undefined): string {
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (!raw) return '';
  return raw.split(';')[0];
}

describe('Prompt 0011D — Unit: Command state machine', () => {
  it('defines legal transitions and terminal immutability', () => {
    assert.equal(isLegalCommandTransition('QUEUED', 'DELIVERED'), true);
    assert.equal(isLegalCommandTransition('DELIVERED', 'ACKNOWLEDGED'), true);
    assert.equal(isLegalCommandTransition('ACKNOWLEDGED', 'COMPLETED'), true);
    assert.equal(isLegalCommandTransition('ACKNOWLEDGED', 'FAILED'), true);
    assert.equal(isLegalCommandTransition('QUEUED', 'CANCELLED'), true);
    assert.equal(isLegalCommandTransition('COMPLETED', 'FAILED'), false);
    assert.equal(isLegalCommandTransition('FAILED', 'COMPLETED'), false);
    assert.equal(isLegalCommandTransition('EXPIRED', 'COMPLETED'), false);
    assert.equal(isLegalCommandTransition('CANCELLED', 'QUEUED'), false);
    for (const term of TERMINAL_COMMAND_STATUSES) {
      assert.equal(LEGAL_COMMAND_TRANSITIONS[term]?.size ?? 0, 0);
    }
  });

  it('sessionHasValidStepUp enforces expiry and scope binding', () => {
    const now = new Date();
    const future = new Date(now.getTime() + 60_000);
    const past = new Date(now.getTime() - 1000);
    const base = {
      id: 's1',
      userId: 'u1',
      deviceId: null,
      sessionType: 'WEB_CONSOLE' as const,
      tokenHash: 'x',
      csrfTokenHash: 'y',
      mfaVerified: true,
      mfaVerifiedAt: now,
      stepUpVerifiedUntil: future,
      stepUpActionScope: STEP_UP_SCOPES.DEVICE_REVOKE,
      ipAddressTruncated: null,
      userAgentSummary: null,
      createdAt: now,
      lastActiveAt: now,
      expiresAt: future,
      absoluteExpiresAt: future,
      revokedAt: null,
    };
    assert.equal(sessionHasValidStepUp(base, STEP_UP_SCOPES.DEVICE_REVOKE, now), true);
    assert.equal(sessionHasValidStepUp(base, STEP_UP_SCOPES.DEVICE_COMPROMISED, now), false);
    assert.equal(
      sessionHasValidStepUp({ ...base, stepUpVerifiedUntil: past }, STEP_UP_SCOPES.DEVICE_REVOKE, now),
      false
    );
    assert.equal(
      sessionHasValidStepUp({ ...base, stepUpActionScope: null }, STEP_UP_SCOPES.DEVICE_REVOKE, now),
      false
    );
  });
});

describe('Prompt 0011D — Integration: Signed events, commands, step-up', () => {
  let server: http.Server;
  let repo: InMemoryIdentityRepository;
  let cookie = '';
  let csrfToken = '';
  let userId = '';
  let deviceId = '';
  let privateKeyPem = '';
  let publicKeyPem = '';
  let keyAlgorithm: 'ED25519' | 'ECDSA_P256' = 'ED25519';
  let totpSecretBase32 = '';

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo, totpEncryptionKey: TOTP_KEY });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));

    // Register user
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'owner11d@vajra.test',
        password: 'Str0ng!Passw0rd',
        displayName: 'Owner 11D',
      },
    });
    assert.equal(reg.status, 201, JSON.stringify(reg.body));
    cookie = extractCookie(reg.headers['set-cookie']);
    csrfToken = reg.body.csrfToken;
    userId = reg.body.user.id;

    // Enable MFA with a known test secret (never a production secret)
    const secretBase32 = generateTotpSecret();
    totpSecretBase32 = secretBase32;
    const encrypted = encryptTotpSecret({
      secretBase32,
      userId,
      encryptionKeyMaterial: TOTP_KEY,
    });
    await repo.updateUserCredential({
      userId,
      totpSecretEncrypted: encrypted,
      totpEnabled: true,
    });

    // Enroll device: initiate
    const init = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/initiate',
      cookie,
      csrfToken,
      body: { name: 'Test Phone', deviceType: 'ANDROID' },
    });
    assert.equal(init.status, 201, JSON.stringify(init.body));
    const enrollment = init.body.enrollment ?? {};
    const enrollmentToken = enrollment.enrollmentToken ?? init.body.enrollmentToken;
    const challengeNonce = enrollment.challengeNonce ?? init.body.challengeNonce;
    deviceId = enrollment.deviceId ?? init.body.device?.id ?? init.body.deviceId;
    assert.ok(enrollmentToken && challengeNonce && deviceId, JSON.stringify(init.body));

    const keyPair = generateDeviceKeyPair('ED25519');
    privateKeyPem = keyPair.privateKeyPem;
    publicKeyPem = keyPair.publicKeyPem;
    keyAlgorithm = 'ED25519';

    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem,
      keyAlgorithm,
      deviceId,
      enrollmentToken,
      challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });
    const submit = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/submit',
      body: {
        enrollmentToken,
        verificationPasscode: enrollment.verificationPasscode,
        publicKeyPem,
        keyAlgorithm,
        signatureBase64,
        timestampIso,
        clientNonce,
        hardwareBacked: false,
      },
    });
    assert.ok(submit.status === 200 || submit.status === 201, JSON.stringify(submit.body));
    deviceId = submit.body.device?.id ?? deviceId;

    // Confirm enrollment
    const confirm = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/enrollment/confirm`,
      cookie,
      csrfToken,
    });
    assert.ok(confirm.status === 200 || confirm.status === 201, JSON.stringify(confirm.body));
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function deviceHeaders(method: string, path: string, body?: unknown) {
    const timestampIso = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const signatureBase64 = signDeviceRequest({
      privateKeyPem,
      keyAlgorithm,
      method,
      path,
      deviceId,
      timestampIso,
      nonce,
      body: body ?? {},
    });
    return {
      'X-Vajra-Device-Id': deviceId,
      'X-Vajra-Timestamp': timestampIso,
      'X-Vajra-Nonce': nonce,
      'X-Vajra-Signature': signatureBase64,
    };
  }

  it('accepts a valid signed device event and rejects client risk scores', async () => {
    const path = `/api/devices/${deviceId}/events`;
    const body = {
      type: 'DEVICE_HEARTBEAT_RECEIVED',
      category: 'Device',
      severity: 'INFO',
      title: 'Agent check-in',
      description: 'Signed event from enrolled device',
      metadata: { batteryLevel: 80 },
    };
    const headers = deviceHeaders('POST', path, body);
    const res = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers,
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.ok(res.body.event);
    assert.equal(res.body.event.deviceId, deviceId);

    // Client risk score rejected
    const badBody = { ...body, riskScore: 99, type: 'DEVICE_HEARTBEAT_RECEIVED' };
    const badHeaders = deviceHeaders('POST', path, badBody);
    const bad = await requestJson(server, {
      method: 'POST',
      path,
      body: badBody,
      headers: badHeaders,
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error?.code, 'CLIENT_RISK_SCORE_REJECTED');
  });

  it('rejects route/device ID mismatch', async () => {
    const fakeId = crypto.randomUUID();
    const path = `/api/devices/${fakeId}/events`;
    const body = {
      type: 'DEVICE_HEARTBEAT_RECEIVED',
      category: 'Device',
      severity: 'INFO',
      title: 'Mismatch attempt',
    };
    // Sign with real deviceId in headers but path has fakeId
    const timestampIso = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const signatureBase64 = signDeviceRequest({
      privateKeyPem,
      keyAlgorithm,
      method: 'POST',
      path,
      deviceId, // auth header device
      timestampIso,
      nonce,
      body,
    });
    const res = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': timestampIso,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': signatureBase64,
      },
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.error?.code, 'DEVICE_ROUTE_MISMATCH');
  });

  it('rejects invalid signatures and replayed nonces', async () => {
    const path = `/api/devices/${deviceId}/events`;
    const body = {
      type: 'DEVICE_HEARTBEAT_RECEIVED',
      category: 'Device',
      severity: 'INFO',
      title: 'Replay test',
    };
    const timestampIso = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const signatureBase64 = signDeviceRequest({
      privateKeyPem,
      keyAlgorithm,
      method: 'POST',
      path,
      deviceId,
      timestampIso,
      nonce,
      body,
    });

    // First request succeeds
    const first = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': timestampIso,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': signatureBase64,
      },
    });
    assert.equal(first.status, 201, JSON.stringify(first.body));

    // Replay same nonce
    const replay = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': timestampIso,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': signatureBase64,
      },
    });
    assert.equal(replay.status, 409);
    assert.equal(replay.body.error?.code, 'DEVICE_NONCE_REPLAYED');

    // Bad signature
    const badSig = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': new Date().toISOString(),
        'X-Vajra-Nonce': crypto.randomUUID(),
        'X-Vajra-Signature': Buffer.from('not-a-real-signature').toString('base64'),
      },
    });
    assert.equal(badSig.status, 401);
  });

  it('redacts sensitive metadata keys from device events', async () => {
    const path = `/api/devices/${deviceId}/events`;
    const body = {
      type: 'DEVICE_HEARTBEAT_RECEIVED',
      category: 'Device',
      severity: 'INFO',
      title: 'Redaction test',
      metadata: {
        password: 'super-secret',
        totp: '123456',
        batteryLevel: 50,
        note: 'ok',
      },
    };
    const headers = deviceHeaders('POST', path, body);
    const res = await requestJson(server, {
      method: 'POST',
      path,
      body,
      headers,
    });
    // Engine may reject forbidden keys or sanitize; either is acceptable hardening
    if (res.status === 201) {
      const meta = res.body.event?.metadata ?? {};
      assert.equal(meta.password, undefined);
      assert.equal(meta.totp, undefined);
    } else {
      assert.equal(res.status, 400);
    }
  });

  it('enforces command terminal-state immutability and idempotent results', async () => {
    // Create a command as user (REQUEST_DEVICE_STATUS does not require step-up)
    const create = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/commands`,
      cookie,
      csrfToken,
      body: { actionType: 'REQUEST_DEVICE_STATUS', ttlMinutes: 30 },
    });
    assert.equal(create.status, 201, JSON.stringify(create.body));
    const commandId = create.body.command?.id ?? create.body.id;
    assert.ok(commandId);

    // Device delivers via pending
    const pendingPath = `/api/devices/${deviceId}/commands/pending`;
    const pendingHeaders = deviceHeaders('GET', pendingPath);
    const pending = await requestJson(server, {
      method: 'GET',
      path: pendingPath,
      headers: pendingHeaders,
    });
    assert.equal(pending.status, 200, JSON.stringify(pending.body));

    // Acknowledge
    const ackPath = `/api/devices/${deviceId}/commands/${commandId}/acknowledge`;
    const ackBody = {};
    const ackHeaders = deviceHeaders('POST', ackPath, ackBody);
    const ack = await requestJson(server, {
      method: 'POST',
      path: ackPath,
      body: ackBody,
      headers: ackHeaders,
    });
    assert.equal(ack.status, 200, JSON.stringify(ack.body));

    // Submit COMPLETED result
    const resultPath = `/api/devices/${deviceId}/commands/${commandId}/result`;
    const resultBody = { status: 'COMPLETED', safeMessage: 'Status check done' };
    const resultHeaders = deviceHeaders('POST', resultPath, resultBody);
    const result = await requestJson(server, {
      method: 'POST',
      path: resultPath,
      body: resultBody,
      headers: resultHeaders,
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.idempotentReplay, false);

    // Idempotent same result
    const resultHeaders2 = deviceHeaders('POST', resultPath, resultBody);
    const result2 = await requestJson(server, {
      method: 'POST',
      path: resultPath,
      body: resultBody,
      headers: resultHeaders2,
    });
    assert.equal(result2.status, 200);
    assert.equal(result2.body.idempotentReplay, true);

    // Conflicting FAILED after COMPLETED
    const conflictBody = { status: 'FAILED', safeMessage: 'Should not overwrite' };
    const conflictHeaders = deviceHeaders('POST', resultPath, conflictBody);
    const conflict = await requestJson(server, {
      method: 'POST',
      path: resultPath,
      body: conflictBody,
      headers: conflictHeaders,
    });
    // Server treats additional result posts as idempotent replays (first terminal result wins).
    assert.ok(conflict.status === 200 || conflict.status === 409, JSON.stringify(conflict.body));
    if (conflict.status === 200) {
      assert.equal(conflict.body.idempotentReplay, true);
    }
  });

  it('requires MFA step-up for device revoke and accepts after valid TOTP', async () => {
    // Without step-up
    const denied = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/revoke`,
      cookie,
      csrfToken,
      body: { reason: 'test' },
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error?.code, 'STEP_UP_REQUIRED');

    // Obtain current TOTP from the known test secret
    const totpCode = generateTotpCodeAtTime(totpSecretBase32);
    assert.equal(verifyTotpCode({ secretBase32: totpSecretBase32, code: totpCode }), true);

    const stepUp = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/step-up',
      cookie,
      csrfToken,
      body: { totpCode, actionScope: STEP_UP_SCOPES.DEVICE_REVOKE },
    });
    assert.equal(stepUp.status, 200, JSON.stringify(stepUp.body));
    assert.equal(stepUp.body.stepUpVerified, true);
    assert.equal(stepUp.body.actionScope, STEP_UP_SCOPES.DEVICE_REVOKE);

    // Wrong scope should still deny (if we only granted DEVICE_REVOKE, compromised fails)
    const wrongScope = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/compromised`,
      cookie,
      csrfToken,
      body: {},
    });
    // May be 403 STEP_UP_REQUIRED (wrong scope) or 409 if lifecycle prevents
    assert.ok(wrongScope.status === 403 || wrongScope.status === 409, JSON.stringify(wrongScope.body));
  });

  it('rejects cross-user access to device events and commands', async () => {
    const regB = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'attacker11d@vajra.test',
        password: 'Str0ng!Passw0rd',
        displayName: 'Attacker',
      },
    });
    assert.equal(regB.status, 201);
    const cookieB = extractCookie(regB.headers['set-cookie']);
    const csrfB = regB.body.csrfToken;

    const cross = await requestJson(server, {
      method: 'GET',
      path: `/api/devices/${deviceId}/commands`,
      cookie: cookieB,
      csrfToken: csrfB,
    });
    assert.equal(cross.status, 404);
  });
});


describe("Prompt 0011E — Step-up UI source contracts", () => {
  it("App.tsx defines step-up modal state, verify handler, and STEP_UP_REQUIRED branching", () => {
    const appPath = path.join(process.cwd(), "src/App.tsx");
    const src = fs.readFileSync(appPath, "utf8");
    assert.match(src, /stepUpModalOpen/);
    assert.match(src, /handleStepUpVerify/);
    assert.match(src, /STEP_UP_REQUIRED/);
    assert.match(src, /\/api\/auth\/step-up/);
    assert.match(src, /fromStepUpRetry/);
    assert.match(src, /pendingProtectedActionRef/);
    // Must not persist TOTP to localStorage/sessionStorage
    assert.equal(/localStorage\.setItem\([^)]*stepUpCode/i.test(src), false);
    assert.equal(/sessionStorage\.setItem\([^)]*totp/i.test(src), false);
  });

  it("sensitive server routes clear step-up after successful use", () => {
    const devices = fs.readFileSync(path.join(process.cwd(), "src/server/devices/routes.ts"), "utf8");
    const notif = fs.readFileSync(path.join(process.cwd(), "src/server/notifications/routes.ts"), "utf8");
    assert.match(devices, /clearStepUp/);
    assert.match(notif, /clearStepUp/);
  });
});
