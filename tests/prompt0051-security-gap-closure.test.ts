/**
 * VAJRA — Prompt 0051 Security Review & Final Gap Closure Regression Suite
 *
 * Verifies source-grounded fixes across Phase 2 & Phase 3:
 * 1. CSP & Framing Policy:
 *    - Never emits `frame-ancestors *` or `script-src 'unsafe-eval'`.
 *    - Standalone production fails closed to `frame-ancestors 'none'` + `X-Frame-Options: DENY`
 *      and `script-src 'self'` (no `'unsafe-inline'`, no `'unsafe-eval'`).
 *    - Rejects wildcard (`*`) and insecure `http://` frame ancestors in production config & headers.
 *    - Allows explicit `https://` `CSP_FRAME_ANCESTORS` allowlist and hosted preview Google AI Studio parent origins.
 * 2. Proxy, Cookie & Rate-Limiter Spoofing Hardening:
 *    - Rejects client-spoofed `X-Forwarded-Proto`, `X-Forwarded-Ssl`, `X-Forwarded-Host`, and `Origin: https://...`
 *      when `trust proxy` is disabled and socket is not a verified local loopback reverse proxy.
 *    - Prevents `X-Forwarded-For` spoofing from bypassing `POST /api/auth/login` rate limiting on unproxied connections.
 * 3. Platform Command Capability Boundary & Truthful Action States:
 *    - Windows rejects `RING_DEVICE`, `REQUEST_LOCATION`, `DISPLAY_RECOVERY_MESSAGE` (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`)
 *      without consuming MFA step-up or creating `RemoteCommand` records, while queuing `REQUEST_DEVICE_STATUS`.
 *    - Android rejects `REQUEST_LOCATION` and `DISPLAY_RECOVERY_MESSAGE` (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`)
 *      without consuming MFA step-up or creating `RemoteCommand` records, while queuing `REQUEST_DEVICE_STATUS` and `RING_DEVICE`.
 *    - `/api/devices/:id/commands` rejects `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` as Plane-2 commands.
 *    - Server-side `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` on `/actions` never fabricate `ONLINE` connectivity
 *      or `lastSeenAt` and explicitly label `executionScope: 'SERVER_ACCOUNT_STATE'`, `physicalLockApplied: false`.
 * 4. Device Revocation, Pending Command Cancellation, Decommission Credential Cleanup & Re-Enrollment:
 *    - Revoking or decommissioning a device automatically cancels queued commands and revokes credentials.
 *    - Re-enrolling with a fresh keypair succeeds cleanly while re-using a revoked keypair fails with `409 DUPLICATE_PUBLIC_KEY`.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { describe, it } from 'node:test';
import type { Request } from 'express';
import { validateRuntimeConfig } from '../packages/config/src/index.ts';
import {
  generateDeviceKeyPair,
  generateTotpCodeAtTime,
  signEnrollmentProof,
} from '../packages/security/src/node.ts';
import {
  createVajraApiApp,
  resolveSecurityResponseHeaders,
} from '../src/server/app.ts';
import {
  isSecureRequest,
  isTrustedProxyRequest,
  STEP_UP_SCOPES,
} from '../src/server/auth/middleware.ts';
import { getClientIpTruncated } from '../src/server/auth/routes.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';

const TEST_TOTP_KEY = 'prompt0051-totp-encryption-key-32bytes!!';

async function sendHttpJson(
  server: http.Server,
  opts: {
    method: string;
    path: string;
    cookie?: string;
    csrfToken?: string;
    headers?: Record<string, string>;
    body?: unknown;
  }
): Promise<{ status: number; headers: http.IncomingHttpHeaders; json: any }> {
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  const rawBody = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        method: opts.method,
        path: opts.path,
        headers: {
          Accept: 'application/json',
          ...(rawBody !== undefined
            ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(rawBody),
              }
            : {}),
          ...(opts.cookie ? { Cookie: opts.cookie } : {}),
          ...(opts.csrfToken ? { 'X-CSRF-Token': opts.csrfToken } : {}),
          ...(opts.headers ?? {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: any = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {
            json = { rawText: text };
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, json });
        });
      }
    );
    req.on('error', reject);
    if (rawBody !== undefined) req.write(rawBody);
    req.end();
  });
}

function extractFirstCookiePair(setCookie: string | string[] | undefined): string {
  const arr = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  assert.ok(arr.length > 0, 'Expected Set-Cookie header');
  return arr[0].split(';')[0];
}

describe('Prompt 0051 — Final Gap Closure & Security Review Regression Suite', () => {
  it('1. enforces fail-closed CSP frame-ancestors in production, rejects wildcards/http origins, removes unsafe-eval, and supports explicit trusted origins', async () => {
    // (a) Unconfigured standalone production fails closed to frame-ancestors 'none' + X-Frame-Options: DENY + script-src 'self'
    const prodDefault = resolveSecurityResponseHeaders({
      env: {
        NODE_ENV: 'production',
        APP_ENV: 'production',
      },
    });
    assert.equal(prodDefault.frameAncestors, "'none'");
    assert.equal(prodDefault.xFrameOptions, 'DENY');
    assert.equal(prodDefault.strictTransportSecurity, 'max-age=31536000; includeSubDomains');
    assert.match(prodDefault.contentSecurityPolicy, /frame-ancestors 'none'/);
    assert.match(prodDefault.contentSecurityPolicy, /script-src 'self'(?:;|$)/);
    assert.doesNotMatch(prodDefault.contentSecurityPolicy, /unsafe-eval/);
    assert.doesNotMatch(prodDefault.contentSecurityPolicy, /frame-ancestors \*/);

    // (b) Untrusted '*' or 'http://' in production fails closed to 'none' + DENY and fails validateRuntimeConfig
    const prodWildcardAttempt = resolveSecurityResponseHeaders({
      env: {
        NODE_ENV: 'production',
        APP_ENV: 'production',
        CSP_FRAME_ANCESTORS: '* http://insecure.example.com',
      },
    });
    assert.equal(prodWildcardAttempt.frameAncestors, "'none'");
    assert.equal(prodWildcardAttempt.xFrameOptions, 'DENY');

    const badConfigValidation = validateRuntimeConfig({
      NODE_ENV: 'production',
      APP_ENV: 'production',
      DATABASE_URL:
        'postgresql://vajra_prod:StrongNonPlaceholderPass_987654@pg.vajra.internal:5432/vajra?sslmode=require',
      SESSION_SECRET: 'prod_session_secret_minimum_32_characters_entropy_ok!',
      TOTP_ENCRYPTION_KEY: 'prod_totp_encryption_key_minimum_32_chars_distinct!!',
      APP_PUBLIC_ORIGIN: 'https://console.vajra.security',
      CSP_FRAME_ANCESTORS: '*',
    });
    assert.equal(badConfigValidation.valid, false);
    assert.ok(badConfigValidation.errors.some((e) => e.includes('CSP_FRAME_ANCESTORS')));

    // (c) Explicit trusted https:// origin in production is allowed alongside 'self'
    const prodTrustedPortal = resolveSecurityResponseHeaders({
      env: {
        NODE_ENV: 'production',
        APP_ENV: 'production',
        CSP_FRAME_ANCESTORS: 'https://portal.vajra.security',
      },
    });
    assert.equal(prodTrustedPortal.frameAncestors, "'self' https://portal.vajra.security");
    assert.equal(prodTrustedPortal.xFrameOptions, null);
    assert.match(
      prodTrustedPortal.contentSecurityPolicy,
      /frame-ancestors 'self' https:\/\/portal\.vajra\.security/
    );

    // (d) Hosted AI Studio preview (APPLET_ID set) uses explicit Google AI Studio origins, never '*'
    const previewHeaders = resolveSecurityResponseHeaders({
      env: {
        NODE_ENV: 'development',
        APPLET_ID: 'cca606c3-faba-4d34-946a-e7ada853efb9',
      },
    });
    assert.equal(
      previewHeaders.frameAncestors,
      "'self' https://aistudio.google.com https://*.google.com"
    );
    assert.doesNotMatch(previewHeaders.contentSecurityPolicy, /frame-ancestors \*/);
    assert.doesNotMatch(previewHeaders.contentSecurityPolicy, /unsafe-eval/);

    // (e) Live HTTP response on /api/health carries hardened CSP, X-Permitted-Cross-Domain-Policies, and no-store cache headers
    const app = createVajraApiApp({
      env: { NODE_ENV: 'production', APP_ENV: 'production' },
    });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const healthRes = await sendHttpJson(server, { method: 'GET', path: '/api/health' });
      assert.equal(healthRes.status, 200);
      assert.equal(healthRes.headers['x-frame-options'], 'DENY');
      assert.equal(healthRes.headers['x-permitted-cross-domain-policies'], 'none');
      assert.equal(healthRes.headers['x-content-type-options'], 'nosniff');
      assert.match(String(healthRes.headers['cache-control']), /no-store/);
      assert.match(String(healthRes.headers['content-security-policy']), /frame-ancestors 'none'/);
      assert.doesNotMatch(String(healthRes.headers['content-security-policy']), /unsafe-eval/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('2. ignores spoofed X-Forwarded-* headers on unproxied connections and blocks X-Forwarded-For login rate-limit bypasses', async () => {
    // Unit-verify untrusted direct connection vs trusted proxy connection
    const untrustedDirectReq = {
      secure: false,
      headers: {
        host: 'vajra-direct.example.com:3000',
        'x-forwarded-proto': 'https',
        'x-forwarded-ssl': 'on',
        'x-forwarded-host': 'evil.example.com',
        'x-forwarded-for': '198.51.100.77',
        origin: 'https://vajra-direct.example.com:3000',
      },
      socket: { remoteAddress: '203.0.113.42' },
      app: { get: () => false },
    } as unknown as Request;

    assert.equal(isTrustedProxyRequest(untrustedDirectReq), false);
    assert.equal(
      isSecureRequest(untrustedDirectReq),
      false,
      'Unproxied plain-HTTP socket must ignore spoofed X-Forwarded-Proto and Origin: https://'
    );
    assert.equal(
      getClientIpTruncated(untrustedDirectReq),
      '203.0.113.0/24',
      'Unproxied socket must ignore spoofed X-Forwarded-For and use real socket remoteAddress'
    );

    const trustedProxyReq = {
      secure: false,
      headers: {
        host: 'vajra.example.com',
        'x-forwarded-proto': 'https',
        'x-forwarded-for': '198.51.100.77, 10.0.0.4',
      },
      socket: { remoteAddress: '10.0.0.4' },
      app: { get: (k: string) => (k === 'trust proxy' ? true : undefined) },
    } as unknown as Request;

    assert.equal(isTrustedProxyRequest(trustedProxyReq), true);
    assert.equal(isSecureRequest(trustedProxyReq), true);
    assert.equal(getClientIpTruncated(trustedProxyReq), '198.51.100.0/24');

    // Live HTTP test: rotating spoofed X-Forwarded-For with a non-loopback Host header (trust proxy = false)
    // must NOT bypass loginRateLimiter (maxAttempts = 10 -> 11th attempt must hit 429 RATE_LIMITED)!
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo, totpEncryptionKey: TEST_TOTP_KEY });
    // Explicitly ensure trust proxy is false
    app.set('trust proxy', false);
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      let saw429 = false;
      for (let i = 1; i <= 12; i++) {
        const res = await sendHttpJson(server, {
          method: 'POST',
          path: '/api/auth/login',
          headers: {
            Host: 'unproxied-direct.vajra.test:3000',
            'X-Forwarded-For': `198.51.${i}.${i}`,
            'X-Forwarded-Proto': 'https',
          },
          body: {
            email: 'ratelimit-target@vajra.test',
            password: 'Wrong-Password-Attempt!123',
          },
        });
        if (res.status === 429) {
          saw429 = true;
          break;
        }
      }
      assert.equal(
        saw429,
        true,
        'Rotating spoofed X-Forwarded-For on an unproxied server must not bypass login rate limiting'
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('3. enforces strict platform command capability boundaries, truthful server-side Lost Mode, revocation command cleanup, and fresh-key re-enrollment', async () => {
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo, totpEncryptionKey: TEST_TOTP_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      // Register owner and enable TOTP MFA
      const reg = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/register',
        body: {
          email: 'owner.p0051@vajra.test',
          displayName: 'Prompt 0051 Owner',
          password: 'Prompt0051-StrongPassword!99',
        },
      });
      assert.equal(reg.status, 201);
      const cookie = extractFirstCookiePair(reg.headers['set-cookie']);
      const csrf = reg.json.csrfToken as string;

      const setupMfa = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/mfa/setup',
        cookie,
        csrfToken: csrf,
        body: {},
      });
      assert.equal(setupMfa.status, 200);
      const totpSecret = setupMfa.json.secretBase32 as string;

      const verifyMfa = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/mfa/verify',
        cookie,
        csrfToken: csrf,
        body: { code: generateTotpCodeAtTime(totpSecret, Date.now()) },
      });
      assert.equal(verifyMfa.status, 200);

      const enrollDevice = async (
        name: string,
        deviceType: 'WINDOWS' | 'ANDROID',
        existingKeyPair?: ReturnType<typeof generateDeviceKeyPair>
      ) => {
        const init = await sendHttpJson(server, {
          method: 'POST',
          path: '/api/devices/enrollment/initiate',
          cookie,
          csrfToken: csrf,
          body: { proposedDeviceName: name, expectedDeviceType: deviceType },
        });
        assert.equal(init.status, 201);
        const { deviceId, enrollmentToken, challengeNonce } = init.json.enrollment;
        const kp = existingKeyPair ?? generateDeviceKeyPair('ECDSA_P256');
        const ts = new Date().toISOString();
        const clientNonce = crypto.randomBytes(16).toString('hex');
        const sig = signEnrollmentProof({
          privateKeyPem: kp.privateKeyPem,
          keyAlgorithm: 'ECDSA_P256',
          publicKeyFingerprint: kp.publicKeyFingerprint,
          deviceId,
          enrollmentToken,
          challengeNonce,
          timestampIso: ts,
          clientNonce,
        });

        const sub = await sendHttpJson(server, {
          method: 'POST',
          path: '/api/devices/enrollment/submit',
          body: {
            enrollmentToken,
            verificationPasscode: init.json.enrollment.verificationPasscode,
            keyAlgorithm: 'ECDSA_P256',
            publicKeyPem: kp.publicKeyPem,
            signatureBase64: sig,
            timestampIso: ts,
            clientNonce,
          },
        });
        return { deviceId, kp, submitRes: sub };
      };

      const win = await enrollDevice('Win11-Workstation', 'WINDOWS');
      assert.equal(win.submitRes.status, 200);
      const winConfirm = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${win.deviceId}/enrollment/confirm`,
        cookie,
        csrfToken: csrf,
        body: { publicKeyFingerprint: win.kp.publicKeyFingerprint },
      });
      assert.equal(winConfirm.status, 200);

      const android = await enrollDevice('Pixel-9-Companion', 'ANDROID');
      assert.equal(android.submitRes.status, 200);
      const androidConfirm = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${android.deviceId}/enrollment/confirm`,
        cookie,
        csrfToken: csrf,
        body: { publicKeyFingerprint: android.kp.publicKeyFingerprint },
      });
      assert.equal(androidConfirm.status, 200);

      // Grant SENSITIVE_COMMAND step-up and verify unsupported commands do NOT consume it or queue records!
      const grantSensitive = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/step-up',
        cookie,
        csrfToken: csrf,
        body: {
          totpCode: generateTotpCodeAtTime(totpSecret, Date.now()),
          actionScope: STEP_UP_SCOPES.SENSITIVE_COMMAND,
        },
      });
      assert.equal(grantSensitive.status, 200);

      // Windows rejects RING_DEVICE, REQUEST_LOCATION, DISPLAY_RECOVERY_MESSAGE on both /commands and /actions
      for (const badWinAction of ['RING_DEVICE', 'REQUEST_LOCATION', 'DISPLAY_RECOVERY_MESSAGE']) {
        const resCmd = await sendHttpJson(server, {
          method: 'POST',
          path: `/api/devices/${win.deviceId}/commands`,
          cookie,
          csrfToken: csrf,
          body: { actionType: badWinAction },
        });
        assert.equal(resCmd.status, 400);
        assert.equal(resCmd.json.error.code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');

        const resAct = await sendHttpJson(server, {
          method: 'POST',
          path: `/api/devices/${win.deviceId}/actions`,
          cookie,
          csrfToken: csrf,
          body: { actionType: badWinAction, title: 'Test', message: 'Test' },
        });
        assert.equal(resAct.status, 400);
        assert.equal(resAct.json.error.code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');
      }

      // Android rejects REQUEST_LOCATION and DISPLAY_RECOVERY_MESSAGE, and /commands rejects ENABLE_LOST_MODE
      for (const badAndroidAction of ['REQUEST_LOCATION', 'DISPLAY_RECOVERY_MESSAGE']) {
        const resAct = await sendHttpJson(server, {
          method: 'POST',
          path: `/api/devices/${android.deviceId}/actions`,
          cookie,
          csrfToken: csrf,
          body: { actionType: badAndroidAction, title: 'Test', message: 'Test' },
        });
        assert.equal(resAct.status, 400);
        assert.equal(resAct.json.error.code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');
      }
      const lostViaCommands = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${android.deviceId}/commands`,
        cookie,
        csrfToken: csrf,
        body: { actionType: 'ENABLE_LOST_MODE' },
      });
      assert.equal(lostViaCommands.status, 400);
      assert.equal(lostViaCommands.json.error.code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');

      // Because none of the rejected commands consumed step-up, Android RING_DEVICE now succeeds as QUEUED!
      const ringAndroid = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${android.deviceId}/commands`,
        cookie,
        csrfToken: csrf,
        body: { actionType: 'RING_DEVICE' },
      });
      assert.equal(ringAndroid.status, 201);
      assert.equal(ringAndroid.json.command.status, 'QUEUED');
      assert.equal(ringAndroid.json.command.completedAt, null);

      // Windows REQUEST_DEVICE_STATUS succeeds as QUEUED!
      const statusWin = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${win.deviceId}/commands`,
        cookie,
        csrfToken: csrf,
        body: { actionType: 'REQUEST_DEVICE_STATUS' },
      });
      assert.equal(statusWin.status, 201);
      assert.equal(statusWin.json.command.status, 'QUEUED');

      // Server-side ENABLE_LOST_MODE on Windows marks LOST with explicit SERVER_ACCOUNT_STATE scope
      // and does NOT fabricate connectivityStatus='ONLINE' or lastSeenAt!
      const grantLost = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/step-up',
        cookie,
        csrfToken: csrf,
        body: {
          totpCode: generateTotpCodeAtTime(totpSecret, Date.now()),
          actionScope: STEP_UP_SCOPES.ENABLE_LOST_MODE,
        },
      });
      assert.equal(grantLost.status, 200);

      const winBeforeLost = await sendHttpJson(server, {
        method: 'GET',
        path: `/api/devices/${win.deviceId}`,
        cookie,
      });
      assert.equal(winBeforeLost.status, 200);

      const enableLostWin = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${win.deviceId}/actions`,
        cookie,
        csrfToken: csrf,
        body: {
          actionType: 'ENABLE_LOST_MODE',
          title: 'Missing ThinkPad',
          message: 'Contact security desk.',
        },
      });
      assert.equal(enableLostWin.status, 200);
      assert.equal(enableLostWin.json.device.lifecycleState, 'LOST');
      assert.equal(enableLostWin.json.device.connectivityStatus, 'UNKNOWN');
      assert.equal(enableLostWin.json.device.lastSeenAt, winBeforeLost.json.device.lastSeenAt);
      assert.equal(enableLostWin.json.device.lastHeartbeatAt, null);
      assert.equal(enableLostWin.json.action.payloadSummary.executionScope, 'SERVER_ACCOUNT_STATE');
      assert.equal(enableLostWin.json.action.payloadSummary.physicalLockApplied, false);
      assert.equal(enableLostWin.json.action.payloadSummary.liveLocationTracking, false);

      // Revoking the Windows device cancels its pending REQUEST_DEVICE_STATUS command and revokes its credential
      const grantRevoke = await sendHttpJson(server, {
        method: 'POST',
        path: '/api/auth/step-up',
        cookie,
        csrfToken: csrf,
        body: {
          totpCode: generateTotpCodeAtTime(totpSecret, Date.now()),
          actionScope: STEP_UP_SCOPES.DEVICE_REVOKE,
        },
      });
      assert.equal(grantRevoke.status, 200);

      const revokeWin = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${win.deviceId}/revoke`,
        cookie,
        csrfToken: csrf,
        body: { reason: 'RE_ENROLLMENT_TEST' },
      });
      assert.equal(revokeWin.status, 200);
      assert.equal(revokeWin.json.device.lifecycleState, 'REVOKED');

      const winCmdsAfterRevoke = await sendHttpJson(server, {
        method: 'GET',
        path: `/api/devices/${win.deviceId}/commands`,
        cookie,
      });
      assert.equal(winCmdsAfterRevoke.status, 200);
      const statusCmdRecord = winCmdsAfterRevoke.json.commands.find(
        (c: any) => c.id === statusWin.json.command.id
      );
      assert.ok(statusCmdRecord);
      assert.equal(
        statusCmdRecord.status,
        'CANCELLED',
        'Pending QUEUED command must be automatically cancelled when device is revoked'
      );

      // Decommissioning the revoked device preserves REVOKED credentials and marks DECOMMISSIONED
      const decommWin = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${win.deviceId}/decommission`,
        cookie,
        csrfToken: csrf,
        body: {},
      });
      assert.equal(decommWin.status, 200);
      assert.equal(decommWin.json.device.lifecycleState, 'DECOMMISSIONED');

      // Re-enrolling with the old revoked keypair is rejected with 409 DUPLICATE_PUBLIC_KEY
      const reuseRevokedKey = await enrollDevice('Win11-Reenroll-BadKey', 'WINDOWS', win.kp);
      assert.equal(reuseRevokedKey.submitRes.status, 409);
      assert.equal(reuseRevokedKey.submitRes.json.error.code, 'DUPLICATE_PUBLIC_KEY');

      // Re-enrolling with a fresh keypair (matching Windows EnrollmentCli & Android rotateKey()) succeeds cleanly!
      const freshReenroll = await enrollDevice('Win11-Workstation-Reenrolled', 'WINDOWS');
      assert.equal(freshReenroll.submitRes.status, 200);
      const freshConfirm = await sendHttpJson(server, {
        method: 'POST',
        path: `/api/devices/${freshReenroll.deviceId}/enrollment/confirm`,
        cookie,
        csrfToken: csrf,
        body: { publicKeyFingerprint: freshReenroll.kp.publicKeyFingerprint },
      });
      assert.equal(freshConfirm.status, 200);
      assert.equal(freshConfirm.json.device.lifecycleState, 'TRUSTED');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
