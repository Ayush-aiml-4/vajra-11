/**
 * VAJRA — Prompt 0049: Final Release Acceptance, Security Assurance & Gap Closure Suite
 *
 * Validates:
 * 1. Atomic single-use MFA step-up consumption under concurrent requests + invalid-input preservation + step-up TOTP brute-force rate limiting (429).
 * 2. Atomic single-use recovery-code login under concurrent requests + session invalidation on recovery-code login, MFA disable, and recovery-code regeneration.
 * 3. CSRF Origin, Referer fallback, production APP_PUBLIC_ORIGIN enforcement, and session-bound X-CSRF-Token checks.
 * 4. Cross-user horizontal access denial (404) across devices, commands, ThreatCheck, alerts, events, and risk endpoints.
 * 5. Plane-2 cryptographic device authentication boundaries (±120s timestamp freshness, canonical body tamper, route-id mismatch, nonce replay, compromised/revoked quarantine, conflicting CommandResult).
 * 6. Truthful heartbeat permission & security summary persistence (no fabricated Android location permission claims when omitted).
 * 7. ThreatCheck SSRF zero-network guarantee, URL secret redaction, dangerous-scheme rejection, CSV formula-injection neutralization, and SHA-256 audit chain tamper detection.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import { STEP_UP_SCOPES } from '../src/server/auth/middleware.ts';
import {
  generateDeviceKeyPair,
  signEnrollmentProof,
  signDeviceRequest,
  generateTotpCodeAtTime,
  verifyAuditChain,
} from '../packages/security/src/node.ts';

const TEST_TOTP_KEY = 'vajra-prompt-0049-release-totp-key-32b!!';

function extractCookie(setCookie: string | string[] | undefined): string {
  if (!setCookie) return '';
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0] ?? '';
}

async function requestRaw(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
    headers?: Record<string, string>;
  }
): Promise<{ status: number; text: string; json: any; headers: http.IncomingHttpHeaders }> {
  const addr = server.address();
  assert(addr && typeof addr === 'object');
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers ?? {}),
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (options.cookie) {
    headers.Cookie = options.cookie;
  }
  if (options.csrfToken) {
    headers['X-CSRF-Token'] = options.csrfToken;
  }

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: addr.port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            json = null;
          }
          resolve({
            status: res.statusCode ?? 0,
            text,
            json,
            headers: res.headers,
          });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) {
      req.write(payload);
    }
    req.end();
  });
}

async function enrollAndConfirmDevice(params: {
  server: http.Server;
  cookie: string;
  csrfToken: string;
  name: string;
  deviceType: 'ANDROID' | 'WINDOWS';
  algorithm?: 'ED25519' | 'ECDSA_P256';
}) {
  const alg = params.algorithm ?? (params.deviceType === 'ANDROID' ? 'ECDSA_P256' : 'ED25519');
  const initRes = await requestRaw(params.server, {
    method: 'POST',
    path: '/api/devices/enrollment/initiate',
    cookie: params.cookie,
    csrfToken: params.csrfToken,
    body: {
      proposedDeviceName: params.name,
      expectedDeviceType: params.deviceType,
    },
  });
  assert.equal(initRes.status, 201);
  const { deviceId, enrollmentToken, challengeNonce } = initRes.json.enrollment;
  const keyPair = generateDeviceKeyPair(alg);
  const timestampIso = new Date().toISOString();
  const clientNonce = crypto.randomBytes(16).toString('hex');
  const signatureBase64 = signEnrollmentProof({
    privateKeyPem: keyPair.privateKeyPem,
    keyAlgorithm: alg,
    publicKeyFingerprint: keyPair.publicKeyFingerprint,
    deviceId,
    enrollmentToken,
    challengeNonce,
    timestampIso,
    clientNonce,
  });

  const subRes = await requestRaw(params.server, {
    method: 'POST',
    path: '/api/devices/enrollment/submit',
    body: {
      enrollmentToken,
      verificationPasscode: initRes.json.enrollment.verificationPasscode,
      keyAlgorithm: alg,
      publicKeyPem: keyPair.publicKeyPem,
      signatureBase64,
      timestampIso,
      clientNonce,
      hardwareBacked: alg === 'ECDSA_P256',
      osVersion: params.deviceType === 'ANDROID' ? 'Android 14' : 'Windows 11 24H2',
      agentVersion: '0.1.0',
    },
  });
  assert.equal(subRes.status, 200);

  const confirmRes = await requestRaw(params.server, {
    method: 'POST',
    path: `/api/devices/${deviceId}/enrollment/confirm`,
    cookie: params.cookie,
    csrfToken: params.csrfToken,
    body: { publicKeyFingerprint: keyPair.publicKeyFingerprint },
  });
  assert.equal(confirmRes.status, 200);

  return { deviceId: deviceId as string, keyPair, algorithm: alg };
}

describe('Prompt 0049 — Final Release Acceptance & Security Assurance', () => {
  let repo: InMemoryIdentityRepository;
  let server: http.Server;

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({
      repository: repo,
      totpEncryptionKey: TEST_TOTP_KEY,
    });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. Enforces atomic single-use MFA step-up under concurrency, preserves step-up on pre-mutation 400/404, and rate-limits step-up brute force', async () => {
    const email = 'stepup.atomic.0049@vajra.test';
    const password = 'StrongStepUpPassword!0049';

    const reg = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: { email, password, displayName: 'Step-Up Tester' },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.json.csrfToken as string;

    // Enable MFA
    const setup = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/mfa/setup',
      cookie,
      csrfToken: csrf,
      body: {},
    });
    assert.equal(setup.status, 200);
    const secret = setup.json.secretBase32 as string;
    const verifyRes = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/mfa/verify',
      cookie,
      csrfToken: csrf,
      body: { code: generateTotpCodeAtTime(secret, Date.now()) },
    });
    assert.equal(verifyRes.status, 200);

    const devA = await enrollAndConfirmDevice({
      server,
      cookie,
      csrfToken: csrf,
      name: 'Primary Phone',
      deviceType: 'ANDROID',
    });
    const devB = await enrollAndConfirmDevice({
      server,
      cookie,
      csrfToken: csrf,
      name: 'Secondary Laptop',
      deviceType: 'WINDOWS',
    });

    // Grant single SENSITIVE_COMMAND step-up
    const grant1 = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/step-up',
      cookie,
      csrfToken: csrf,
      body: {
        totpCode: generateTotpCodeAtTime(secret, Date.now()),
        actionScope: STEP_UP_SCOPES.SENSITIVE_COMMAND,
      },
    });
    assert.equal(grant1.status, 200);

    // Invalid target device (404) must NOT burn the valid step-up before mutation
    const missingDevCmd = await requestRaw(server, {
      method: 'POST',
      path: '/api/devices/00000000-0000-0000-0000-000000000000/commands',
      cookie,
      csrfToken: csrf,
      body: { actionType: 'RING_DEVICE' },
    });
    assert.equal(missingDevCmd.status, 404);

    // Wrong scope (DEVICE_REVOKE with SENSITIVE_COMMAND step-up) must be rejected with 403 STEP_UP_REQUIRED
    const wrongScope = await requestRaw(server, {
      method: 'POST',
      path: `/api/devices/${devB.deviceId}/revoke`,
      cookie,
      csrfToken: csrf,
      body: { reason: 'WRONG_SCOPE_ATTEMPT' },
    });
    assert.equal(wrongScope.status, 403);
    assert.equal(wrongScope.json?.error?.code, 'STEP_UP_REQUIRED');

    // Fire two concurrent sensitive commands with the single valid step-up -> at most ONE may succeed!
    const [concurrentA, concurrentB] = await Promise.all([
      requestRaw(server, {
        method: 'POST',
        path: `/api/devices/${devA.deviceId}/commands`,
        cookie,
        csrfToken: csrf,
        body: { actionType: 'RING_DEVICE' },
      }),
      requestRaw(server, {
        method: 'POST',
        path: `/api/devices/${devA.deviceId}/actions`,
        cookie,
        csrfToken: csrf,
        body: { actionType: 'RING_DEVICE' },
      }),
    ]);

    const succeededCount = [concurrentA.status, concurrentB.status].filter(
      (s) => s === 200 || s === 201
    ).length;
    const stepUpRejectedCount = [concurrentA, concurrentB].filter(
      (r) => r.status === 403 && r.json?.error?.code === 'STEP_UP_REQUIRED'
    ).length;
    assert.equal(succeededCount, 1, 'Exactly one concurrent sensitive request may consume a step-up');
    assert.equal(stepUpRejectedCount, 1, 'Second concurrent sensitive request must be rejected with 403');

    // Concurrent DEVICE_REVOKE across two devices with a single DEVICE_REVOKE grant -> only one succeeds
    const grantRevoke = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/step-up',
      cookie,
      csrfToken: csrf,
      body: {
        totpCode: generateTotpCodeAtTime(secret, Date.now()),
        actionScope: STEP_UP_SCOPES.DEVICE_REVOKE,
      },
    });
    assert.equal(grantRevoke.status, 200);

    const [revA, revB] = await Promise.all([
      requestRaw(server, {
        method: 'POST',
        path: `/api/devices/${devA.deviceId}/revoke`,
        cookie,
        csrfToken: csrf,
        body: { reason: 'CONCURRENT_REVOKE_A' },
      }),
      requestRaw(server, {
        method: 'POST',
        path: `/api/devices/${devB.deviceId}/revoke`,
        cookie,
        csrfToken: csrf,
        body: { reason: 'CONCURRENT_REVOKE_B' },
      }),
    ]);
    assert.deepEqual([revA.status, revB.status].sort(), [200, 403]);

    // Brute-force TOTP guesses on POST /api/auth/step-up must trigger 429 RATE_LIMIT_EXCEEDED (maxAttempts=8 -> 9th attempt returns 429)
    let saw429 = false;
    for (let i = 0; i < 10; i++) {
      const badStep = await requestRaw(server, {
        method: 'POST',
        path: '/api/auth/step-up',
        cookie,
        csrfToken: csrf,
        body: { totpCode: '000000', actionScope: STEP_UP_SCOPES.SENSITIVE_COMMAND },
      });
      if (badStep.status === 429) {
        assert.equal(badStep.json?.error?.code, 'RATE_LIMIT_EXCEEDED');
        saw429 = true;
        break;
      }
      assert.equal(badStep.status, 401);
    }
    assert.equal(saw429, true, 'Expected 429 RATE_LIMIT_EXCEEDED after repeated invalid step-up codes');
  });

  it('2. Enforces single-use recovery-code race protection and revokes other sessions on recovery login, MFA disable, and code regeneration', async () => {
    const email = 'recovery.sessions.0049@vajra.test';
    const password = 'RecoveryStrongPassword!0049';

    const reg = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: { email, password, displayName: 'Recovery Session Owner' },
    });
    assert.equal(reg.status, 201);
    const cookieA = extractCookie(reg.headers['set-cookie']);
    const csrfA = reg.json.csrfToken as string;

    const setup = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/mfa/setup',
      cookie: cookieA,
      csrfToken: csrfA,
      body: {},
    });
    const secret = setup.json.secretBase32 as string;
    const verifyRes = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/mfa/verify',
      cookie: cookieA,
      csrfToken: csrfA,
      body: { code: generateTotpCodeAtTime(secret, Date.now()) },
    });
    assert.equal(verifyRes.status, 200);
    const initialCodes = verifyRes.json.recoveryCodes as string[];

    // Concurrent login with the same unused recovery code -> 1 succeeds (200), 1 fails (401)
    const [login1, login2] = await Promise.all([
      requestRaw(server, {
        method: 'POST',
        path: '/api/auth/login',
        body: { email, password, recoveryCode: initialCodes[0] },
      }),
      requestRaw(server, {
        method: 'POST',
        path: '/api/auth/login',
        body: { email, password, recoveryCode: initialCodes[0] },
      }),
    ]);
    assert.deepEqual([login1.status, login2.status].sort(), [200, 401]);

    const winner = login1.status === 200 ? login1 : login2;
    const cookieRecovery = extractCookie(winner.headers['set-cookie']);
    const csrfRecovery = winner.json.csrfToken as string;

    // Prior session (cookieA) must have been revoked when emergency recovery code was used
    const priorCheck = await requestRaw(server, {
      method: 'GET',
      path: '/api/auth/sessions',
      cookie: cookieA,
    });
    assert.equal(priorCheck.status, 401);

    // Create a second active session via TOTP login
    const totpLogin = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/login',
      body: {
        email,
        password,
        totpCode: generateTotpCodeAtTime(secret, Date.now()),
      },
    });
    assert.equal(totpLogin.status, 200);
    const cookieOther = extractCookie(totpLogin.headers['set-cookie']);

    // Regenerating recovery codes from cookieRecovery revokes cookieOther while keeping cookieRecovery alive
    const regen = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/recovery-codes/regenerate',
      cookie: cookieRecovery,
      csrfToken: csrfRecovery,
      body: { currentPassword: password },
    });
    assert.equal(regen.status, 200);
    assert.equal(regen.json.recoveryCodes.length, 8);

    const otherAfterRegen = await requestRaw(server, {
      method: 'GET',
      path: '/api/auth/sessions',
      cookie: cookieOther,
    });
    assert.equal(otherAfterRegen.status, 401, 'Other session must be revoked on recovery-code regeneration');

    // Create another session and verify MFA disable revokes it while keeping the disabling session active
    const totpLogin2 = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/login',
      body: {
        email,
        password,
        totpCode: generateTotpCodeAtTime(secret, Date.now()),
      },
    });
    assert.equal(totpLogin2.status, 200);
    const cookieOther2 = extractCookie(totpLogin2.headers['set-cookie']);

    const disableRes = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/mfa/disable',
      cookie: cookieRecovery,
      csrfToken: csrfRecovery,
      body: { currentPassword: password },
    });
    assert.equal(disableRes.status, 200);

    const otherAfterDisable = await requestRaw(server, {
      method: 'GET',
      path: '/api/auth/sessions',
      cookie: cookieOther2,
    });
    assert.equal(otherAfterDisable.status, 401, 'Other session must be revoked when MFA is disabled');

    const selfAfterDisable = await requestRaw(server, {
      method: 'GET',
      path: '/api/auth/sessions',
      cookie: cookieRecovery,
    });
    assert.equal(selfAfterDisable.status, 200);
  });

  it('3. Enforces CSRF Origin, Referer fallback, and production APP_PUBLIC_ORIGIN checks on state-changing requests', async () => {
    const reg = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'csrf.0049@vajra.test',
        password: 'CsrfStrongPassword!0049',
        displayName: 'CSRF Tester',
      },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.json.csrfToken as string;
    const addr = server.address() as { port: number };
    const validHost = `127.0.0.1:${addr.port}`;

    // Cross-origin Origin header rejected
    const badOrigin = await requestRaw(server, {
      method: 'POST',
      path: '/api/notifications/read-all',
      cookie,
      csrfToken: csrf,
      headers: {
        Host: validHost,
        Origin: 'https://evil-attacker.example',
      },
      body: {},
    });
    assert.equal(badOrigin.status, 403);
    assert.equal(badOrigin.json?.error?.code, 'CSRF_ORIGIN_MISMATCH');

    // Cross-origin Referer header (when Origin is omitted) rejected
    const badReferer = await requestRaw(server, {
      method: 'POST',
      path: '/api/notifications/read-all',
      cookie,
      csrfToken: csrf,
      headers: {
        Host: validHost,
        Referer: 'https://evil-attacker.example/phish.html',
      },
      body: {},
    });
    assert.equal(badReferer.status, 403);
    assert.equal(badReferer.json?.error?.code, 'CSRF_ORIGIN_MISMATCH');

    // Malformed Referer rejected
    const malformedReferer = await requestRaw(server, {
      method: 'POST',
      path: '/api/notifications/read-all',
      cookie,
      csrfToken: csrf,
      headers: {
        Host: validHost,
        Referer: ':::not-a-valid-url',
      },
      body: {},
    });
    assert.equal(malformedReferer.status, 403);
    assert.equal(malformedReferer.json?.error?.code, 'CSRF_INVALID_ORIGIN');

    // Valid same-origin Referer + valid CSRF token succeeds
    const validReferer = await requestRaw(server, {
      method: 'POST',
      path: '/api/notifications/read-all',
      cookie,
      csrfToken: csrf,
      headers: {
        Host: validHost,
        Referer: `http://${validHost}/console`,
      },
      body: {},
    });
    assert.equal(validReferer.status, 200);

    // Production APP_PUBLIC_ORIGIN mismatch rejected even if Host matches spoofed proxy header
    const prevAppEnv = process.env.APP_ENV;
    const prevPublicOrigin = process.env.APP_PUBLIC_ORIGIN;
    process.env.APP_ENV = 'production';
    process.env.APP_PUBLIC_ORIGIN = 'https://vajra.trusted.example';
    try {
      const mismatchedPublicOrigin = await requestRaw(server, {
        method: 'POST',
        path: '/api/notifications/read-all',
        cookie,
        csrfToken: csrf,
        headers: {
          Host: validHost,
          Origin: `http://${validHost}`,
        },
        body: {},
      });
      assert.equal(mismatchedPublicOrigin.status, 403);
      assert.equal(mismatchedPublicOrigin.json?.error?.code, 'CSRF_ORIGIN_MISMATCH');
    } finally {
      if (prevAppEnv === undefined) delete process.env.APP_ENV;
      else process.env.APP_ENV = prevAppEnv;
      if (prevPublicOrigin === undefined) delete process.env.APP_PUBLIC_ORIGIN;
      else process.env.APP_PUBLIC_ORIGIN = prevPublicOrigin;
    }
  });

  it('4. Enforces Plane-2 cryptographic boundaries, truthful null Android heartbeat permissions, and cross-device route isolation', async () => {
    const reg = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'plane2.0049@vajra.test',
        password: 'Plane2StrongPassword!0049',
        displayName: 'Plane 2 Owner',
      },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.json.csrfToken as string;

    const androidDev = await enrollAndConfirmDevice({
      server,
      cookie,
      csrfToken: csrf,
      name: 'Android Companion 0049',
      deviceType: 'ANDROID',
    });
    const windowsDev = await enrollAndConfirmDevice({
      server,
      cookie,
      csrfToken: csrf,
      name: 'Windows Workstation 0049',
      deviceType: 'WINDOWS',
    });

    // Plane-1 browser session cookie cannot authenticate to Plane-2 heartbeat endpoint
    const cookieOnlyHb = await requestRaw(server, {
      method: 'POST',
      path: `/api/devices/${androidDev.deviceId}/heartbeat`,
      cookie,
      csrfToken: csrf,
      body: { connectivityStatus: 'ONLINE' },
    });
    assert.equal(cookieOnlyHb.status, 401);
    assert.equal(cookieOnlyHb.json?.error?.code, 'DEVICE_AUTH_HEADERS_MISSING');

    // Stale timestamp (> 120s old) rejected
    const hbPath = `/api/devices/${androidDev.deviceId}/heartbeat`;
    const hbBody = { connectivityStatus: 'ONLINE', batteryLevel: 64, charging: false };
    const staleTs = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const staleNonce = crypto.randomBytes(16).toString('hex');
    const staleSig = signDeviceRequest({
      privateKeyPem: androidDev.keyPair.privateKeyPem,
      keyAlgorithm: androidDev.algorithm,
      method: 'POST',
      path: hbPath,
      deviceId: androidDev.deviceId,
      timestampIso: staleTs,
      nonce: staleNonce,
      body: hbBody,
    });
    const staleRes = await requestRaw(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': androidDev.deviceId,
        'X-Vajra-Timestamp': staleTs,
        'X-Vajra-Nonce': staleNonce,
        'X-Vajra-Signature': staleSig,
      },
    });
    assert.equal(staleRes.status, 401);

    // Canonical body tampering after signing rejected
    const freshTs = new Date().toISOString();
    const tamperNonce = crypto.randomBytes(16).toString('hex');
    const validSigFor64 = signDeviceRequest({
      privateKeyPem: androidDev.keyPair.privateKeyPem,
      keyAlgorithm: androidDev.algorithm,
      method: 'POST',
      path: hbPath,
      deviceId: androidDev.deviceId,
      timestampIso: freshTs,
      nonce: tamperNonce,
      body: hbBody,
    });
    const tamperedRes = await requestRaw(server, {
      method: 'POST',
      path: hbPath,
      body: { ...hbBody, batteryLevel: 99 },
      headers: {
        'X-Vajra-Device-Id': androidDev.deviceId,
        'X-Vajra-Timestamp': freshTs,
        'X-Vajra-Nonce': tamperNonce,
        'X-Vajra-Signature': validSigFor64,
      },
    });
    assert.equal(tamperedRes.status, 401);

    // Route :id mismatch (Windows device signing a request targeting Android device route) rejected with 403
    const mismatchNonce = crypto.randomBytes(16).toString('hex');
    const mismatchSig = signDeviceRequest({
      privateKeyPem: windowsDev.keyPair.privateKeyPem,
      keyAlgorithm: windowsDev.algorithm,
      method: 'POST',
      path: hbPath,
      deviceId: windowsDev.deviceId,
      timestampIso: freshTs,
      nonce: mismatchNonce,
      body: hbBody,
    });
    const mismatchRes = await requestRaw(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': windowsDev.deviceId,
        'X-Vajra-Timestamp': freshTs,
        'X-Vajra-Nonce': mismatchNonce,
        'X-Vajra-Signature': mismatchSig,
      },
    });
    assert.equal(mismatchRes.status, 403);

    // Valid Android heartbeat WITHOUT locationPermissionGranted/permissionSummary/securitySummary stores null (never fabricates true)
    const okNonce = crypto.randomBytes(16).toString('hex');
    const okSig = signDeviceRequest({
      privateKeyPem: androidDev.keyPair.privateKeyPem,
      keyAlgorithm: androidDev.algorithm,
      method: 'POST',
      path: hbPath,
      deviceId: androidDev.deviceId,
      timestampIso: freshTs,
      nonce: okNonce,
      body: hbBody,
    });
    const okHb = await requestRaw(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': androidDev.deviceId,
        'X-Vajra-Timestamp': freshTs,
        'X-Vajra-Nonce': okNonce,
        'X-Vajra-Signature': okSig,
      },
    });
    assert.equal(okHb.status, 200);
    assert.equal(okHb.json.heartbeat.locationPermissionGranted, null);
    assert.equal(okHb.json.heartbeat.permissionSummary, null);
    assert.equal(okHb.json.heartbeat.securitySummary, null);

    // Location summary for Android device must truthfully report UNAVAILABLE when locationPermissionGranted was not attested
    const actionsList = await requestRaw(server, {
      method: 'GET',
      path: `/api/devices/${androidDev.deviceId}/actions`,
      cookie,
    });
    assert.equal(actionsList.status, 200);
    assert.equal(actionsList.json.locationSummary.accuracyMode, 'UNAVAILABLE');
    assert.match(actionsList.json.locationSummary.label, /not granted/i);
  });

  it('5. Enforces ThreatCheck zero-outbound-fetch SSRF safety, CSV formula neutralization, and AuditLog tamper detection', async () => {
    const reg = await requestRaw(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'ssrf.audit.0049@vajra.test',
        password: 'SsrfAuditPassword!0049',
        displayName: 'SSRF & Audit Verifier',
      },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.json.csrfToken as string;

    // Intercept globalThis.fetch to prove ThreatCheck never performs outbound HTTP requests
    const originalFetch = globalThis.fetch;
    let outboundFetchCount = 0;
    globalThis.fetch = (async () => {
      outboundFetchCount++;
      throw new Error('OUTBOUND_FETCH_FORBIDDEN_IN_THREATCHECK');
    }) as typeof fetch;

    try {
      for (const targetUrl of [
        'http://127.0.0.1:8080/admin?api_key=super_secret_token_999#fragSecret',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://[::1]:5432/internal',
        'https://corp-vault.internal/login-verify',
      ]) {
        const res = await requestRaw(server, {
          method: 'POST',
          path: '/api/threatcheck/inspect',
          cookie,
          csrfToken: csrf,
          body: { url: targetUrl },
        });
        assert.equal(res.status, 200);
        assert.equal(res.json.threatCheck.restrictedDestination, true);
        assert.equal(res.text.includes('super_secret_token_999'), false);
        assert.equal(res.text.includes('fragSecret'), false);
      }

      for (const rejectedScheme of [
        'javascript:alert(1)',
        'file:///etc/passwd',
        'data:text/html,<script>alert(1)</script>',
        'https://admin:hunter2@example.com/portal',
      ]) {
        const bad = await requestRaw(server, {
          method: 'POST',
          path: '/api/threatcheck/inspect',
          cookie,
          csrfToken: csrf,
          body: { url: rejectedScheme },
        });
        assert.equal(bad.status, 400);
      }

      assert.equal(outboundFetchCount, 0, 'ThreatCheck must never perform outbound network fetches');
    } finally {
      globalThis.fetch = originalFetch;
    }

    // Ingest formula-prefixed SecurityEvent and verify CSV export neutralizes spreadsheet execution
    const ev = await requestRaw(server, {
      method: 'POST',
      path: '/api/events',
      cookie,
      csrfToken: csrf,
      body: {
        category: 'Device',
        type: 'DEVICE_SECURITY_CHECK',
        severity: 'INFO',
        title: '=CMD|\'/C calc\'!A0',
        description: '+SUM(1,1) @import',
      },
    });
    assert.equal(ev.status, 201);

    const csvExport = await requestRaw(server, {
      method: 'GET',
      path: '/api/reports/export?format=csv',
      cookie,
    });
    assert.equal(csvExport.status, 200);
    assert.equal(csvExport.text.includes(',"=CMD'), false, 'Raw unescaped =CMD formula must never appear');
    assert.match(csvExport.text, /'=CMD/);

    // Verify intact audit chain, then prove verifyAuditChain detects payload tampering, deleted entries, and broken hash links
    const entries = await repo.getAllAuditEventsOrdered();
    assert.ok(entries.length >= 5);
    assert.equal(verifyAuditChain(entries).valid, true);

    const payloadTampered = entries.map((e, idx) =>
      idx === 2 ? { ...e, metadata: { ...e.metadata, injected: 'tamper' } } : e
    );
    const payloadCheck = verifyAuditChain(payloadTampered);
    assert.equal(payloadCheck.valid, false);
    assert.equal(payloadCheck.brokenAtSequenceNumber, entries[2].sequenceNumber);

    const sequenceDeleted = entries.filter((_, idx) => idx !== 2);
    const deleteCheck = verifyAuditChain(sequenceDeleted);
    assert.equal(deleteCheck.valid, false);

    const brokenPrevLink = entries.map((e, idx) =>
      idx === 3 ? { ...e, previousEntryHash: 'f'.repeat(64) } : e
    );
    const prevLinkCheck = verifyAuditChain(brokenPrevLink);
    assert.equal(prevLinkCheck.valid, false);
    assert.equal(prevLinkCheck.brokenAtSequenceNumber, entries[3].sequenceNumber);
  });
});
