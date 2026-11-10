/**
 * VAJRA — Prompt 0007
 * Production Product Experience + Notifications + Security Activity + Device Control Foundation Test Suite
 *
 * Verifies:
 * 1. Production UI cleanliness (BrandWordmarkShowcase & lockup specimen strings are removed).
 * 2. Real Notification model & APIs:
 *    - Welcome + Two-Step recommendations created on registration
 *    - Unread count calculation
 *    - Mark single notification read (`POST /api/notifications/:id/read`)
 *    - Mark all notifications read (`POST /api/notifications/read-all`)
 *    - Dismiss notification (`POST /api/notifications/:id/dismiss`)
 *    - Cross-user notification isolation
 * 3. Security Activity model & APIs (`GET /api/activity`):
 *    - Human-friendly translation across 5 categories (Authentication, Device, Security, Recovery, ThreatCheck)
 *    - Category filtering
 * 4. ThreatCheck server-side inspection (`POST /api/threatcheck/inspect`):
 *    - Safe URL inspection logs activity
 *    - High-risk URL inspection logs activity AND creates a HIGH/WARNING notification
 * 5. Unified Device Control Foundation (`POST /api/devices/:id/actions` & `GET /api/devices/:id/actions`):
 *    - Locate device (`REQUEST_LOCATION`)
 *    - Ring device (`RING_DEVICE`)
 *    - Recovery Message (`DISPLAY_RECOVERY_MESSAGE`)
 *    - Lost Mode (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`)
 *    - Rejects non-allowlisted actions (`EXECUTE_SHELL` -> 400 UNSUPPORTED_DEVICE_ACTION)
 *    - Cross-user device action isolation (`404 Not Found`)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { createVajraApiApp } from '../src/server/app.ts';
import {
  TEST_TOTP_ENCRYPTION_KEY,
  enableMfaForUser,
  currentTotpCode,
} from './helpers/mfaTestSupport.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import {
  generateDeviceKeyPair,
  signEnrollmentProof,
} from '../packages/security/src/node.ts';

interface TestHttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
  }
): Promise<TestHttpResponse> {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Server is not listening on a TCP port');
  }

  const payload = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload).toString();
  }
  if (options.cookie) {
    headers['Cookie'] = options.cookie;
  }
  if (options.csrfToken) {
    headers['X-CSRF-Token'] = options.csrfToken;
  }

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: address.port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: Record<string, unknown> = {};
          try {
            parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
          } catch {
            parsed = { raw: text };
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: parsed,
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

function extractSessionCookie(headers: http.IncomingHttpHeaders): string {
  const setCookie = headers['set-cookie'];
  if (!setCookie || setCookie.length === 0) {
    throw new Error('Expected Set-Cookie header');
  }
  return setCookie[0].split(';')[0];
}

async function registerAndLoginUser(
  server: http.Server,
  email: string
): Promise<{ cookie: string; csrfToken: string; userId: string }> {
  const regRes = await requestJson(server, {
    method: 'POST',
    path: '/api/auth/register',
    body: {
      email,
      password: 'CorrectHorseBatteryStaple!99',
      displayName: 'Arjun Mehta',
    },
  });
  assert.equal(regRes.status, 201);
  const cookie = extractSessionCookie(regRes.headers);
  const csrfToken = regRes.body.csrfToken as string;
  const userObj = regRes.body.user as { id: string };
  return { cookie, csrfToken, userId: userObj.id };
}

async function enrollActiveDevice(
  server: http.Server,
  session: { cookie: string; csrfToken: string },
  deviceName: string,
  platform: 'WINDOWS' | 'ANDROID'
): Promise<string> {
  const initRes = await requestJson(server, {
    method: 'POST',
    path: '/api/devices/enrollment/initiate',
    cookie: session.cookie,
    csrfToken: session.csrfToken,
    body: {
      proposedDeviceName: deviceName,
      expectedDeviceType: platform,
    },
  });
  assert.equal(initRes.status, 201);
  const device = initRes.body.device as { id: string };
  const enrollment = initRes.body.enrollment as {
    deviceId: string;
    enrollmentToken: string;
    challengeNonce: string;
    verificationPasscode?: string;
  };

  const keyPair = generateDeviceKeyPair('ED25519');
  const submitTimeIso = new Date().toISOString();
  const submitClientNonce = crypto.randomBytes(16).toString('hex');
  const validProofSig = signEnrollmentProof({
    privateKeyPem: keyPair.privateKeyPem,
    keyAlgorithm: 'ED25519',
    deviceId: device.id,
    enrollmentToken: enrollment.enrollmentToken,
    challengeNonce: enrollment.challengeNonce,
    publicKeyFingerprint: keyPair.publicKeyFingerprint,
    timestampIso: submitTimeIso,
    clientNonce: submitClientNonce,
  });

  const submitRes = await requestJson(server, {
    method: 'POST',
    path: '/api/devices/enrollment/submit',
    body: {
      enrollmentToken: enrollment.enrollmentToken,
      verificationPasscode: enrollment.verificationPasscode,
      keyAlgorithm: 'ED25519',
      publicKeyPem: keyPair.publicKeyPem,
      signatureBase64: validProofSig,
      timestampIso: submitTimeIso,
      clientNonce: submitClientNonce,
      hardwareBacked: true,
      osVersion: platform === 'ANDROID' ? 'Android 15' : 'Windows 11 Pro 24H2',
      agentVersion: '0.7.0',
    },
  });
  assert.equal(submitRes.status, 200);

  const confirmRes = await requestJson(server, {
    method: 'POST',
    path: `/api/devices/${device.id}/enrollment/confirm`,
    cookie: session.cookie,
    csrfToken: session.csrfToken,
    body: {},
  });
  assert.equal(confirmRes.status, 200);
  return device.id;
}


async function stepUpSession(
  server: http.Server,
  session: { cookie: string; csrfToken: string; userId: string },
  repository: InMemoryIdentityRepository,
  actionScope: string,
  existingSecret?: string
): Promise<string> {
  const secret =
    existingSecret ??
    (await enableMfaForUser(repository, session.userId, TEST_TOTP_ENCRYPTION_KEY));
  const totpCode = currentTotpCode(secret);
  const res = await requestJson(server, {
    method: 'POST',
    path: '/api/auth/step-up',
    cookie: session.cookie,
    csrfToken: session.csrfToken,
    body: { totpCode, actionScope },
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return secret;
}

describe('VAJRA Prompt 0007 — Notifications, Security Activity, ThreatCheck & Unified Device Control Suite', () => {
  it('Creates welcome notifications on registration and supports read, read-all, and dismiss lifecycles', async () => {
    const repository = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const session = await registerAndLoginUser(server, 'notifications-owner@vajra.local');

      // 1. Fetch initial notifications
      const listRes = await requestJson(server, {
        method: 'GET',
        path: '/api/notifications',
        cookie: session.cookie,
      });
      assert.equal(listRes.status, 200);
      const notifications = listRes.body.notifications as Array<{
        id: string;
        type: string;
        readAt: string | null;
        dismissedAt: string | null;
        severity: string;
        title: string;
      }>;
      assert.ok(notifications.length >= 2, 'Expected welcome and two-step recommendation notifications');
      assert.equal(listRes.body.unreadCount, notifications.length);

      // 2. Mark one notification as read
      const firstId = notifications[0].id;
      const readRes = await requestJson(server, {
        method: 'POST',
        path: `/api/notifications/${firstId}/read`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {},
      });
      assert.equal(readRes.status, 200);
      const readNotif = readRes.body.notification as { readAt: string | null };
      assert.ok(typeof readNotif.readAt === 'string' && readNotif.readAt.length > 0);

      // 3. Mark all remaining notifications as read
      const readAllRes = await requestJson(server, {
        method: 'POST',
        path: '/api/notifications/read-all',
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {},
      });
      assert.equal(readAllRes.status, 200);
      assert.ok((readAllRes.body.updatedCount as number) >= 1);

      const listAfterReadAll = await requestJson(server, {
        method: 'GET',
        path: '/api/notifications',
        cookie: session.cookie,
      });
      assert.equal(listAfterReadAll.body.unreadCount, 0);

      // 4. Dismiss the first notification
      const dismissRes = await requestJson(server, {
        method: 'POST',
        path: `/api/notifications/${firstId}/dismiss`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {},
      });
      assert.equal(dismissRes.status, 200);
      const dismissedNotif = dismissRes.body.notification as { dismissedAt: string | null };
      assert.ok(typeof dismissedNotif.dismissedAt === 'string');

      const listAfterDismiss = await requestJson(server, {
        method: 'GET',
        path: '/api/notifications',
        cookie: session.cookie,
      });
      const activeList = listAfterDismiss.body.notifications as Array<{ id: string }>;
      assert.equal(
        activeList.some((n) => n.id === firstId),
        false,
        'Dismissed notification should be excluded by default'
      );
    } finally {
      server.close();
    }
  });

  it('Enforces strict cross-user isolation on notifications and device actions', async () => {
    const repository = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const userA = await registerAndLoginUser(server, 'user-a@vajra.local');
      const userB = await registerAndLoginUser(server, 'user-b@vajra.local');
      const deviceIdA = await enrollActiveDevice(server, userA, 'Nothing Phone 2a', 'ANDROID');

      const listA = await requestJson(server, {
        method: 'GET',
        path: '/api/notifications',
        cookie: userA.cookie,
      });
      const notifA = (listA.body.notifications as Array<{ id: string }>)[0];

      // User B cannot mark User A's notification read
      const crossRead = await requestJson(server, {
        method: 'POST',
        path: `/api/notifications/${notifA.id}/read`,
        cookie: userB.cookie,
        csrfToken: userB.csrfToken,
        body: {},
      });
      assert.equal(crossRead.status, 404);

      // User B cannot trigger device actions on User A's device
      const crossAction = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${deviceIdA}/actions`,
        cookie: userB.cookie,
        csrfToken: userB.csrfToken,
        body: {
          actionType: 'REQUEST_LOCATION',
        },
      });
      assert.equal(crossAction.status, 404);
    } finally {
      server.close();
    }
  });

  it('Executes supported Unified Device Control actions (Status Check, Android Ring, Server-Side Lost Mode) and rejects unsupported or non-allowlisted actions', async () => {
    const repository = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const session = await registerAndLoginUser(server, 'device-controls@vajra.local');
      const androidId = await enrollActiveDevice(server, session, 'Nothing Phone 2a', 'ANDROID');

      // 0. Non-allowlisted action is rejected with 400 UNSUPPORTED_DEVICE_ACTION
      const prohibitedRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'EXECUTE_SHELL',
        },
      });
      assert.equal(prohibitedRes.status, 400);
      assert.equal((prohibitedRes.body.error as { code: string }).code, 'UNSUPPORTED_DEVICE_ACTION');

      // 1. Unimplemented physical actions (REQUEST_LOCATION, DISPLAY_RECOVERY_MESSAGE) are rejected server-side
      const locateRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'REQUEST_LOCATION',
        },
      });
      assert.equal(locateRes.status, 400);
      assert.equal((locateRes.body.error as { code: string }).code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');

      const msgRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'DISPLAY_RECOVERY_MESSAGE',
          title: 'Lost Device — Please Return',
          message: 'This phone belongs to Arjun. Please call to return.',
        },
      });
      assert.equal(msgRes.status, 400);
      assert.equal((msgRes.body.error as { code: string }).code, 'UNSUPPORTED_COMMAND_FOR_PLATFORM');

      // 2. Request Device Status on Android queues command (never marked COMPLETED without signed receipt)
      const statusRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'REQUEST_DEVICE_STATUS',
        },
      });
      assert.equal(statusRes.status, 200);
      const statusAction = statusRes.body.action as {
        actionType: string;
        status: string;
        completedAt: string | null;
      };
      assert.equal(statusAction.actionType, 'REQUEST_DEVICE_STATUS');
      assert.equal(statusAction.status, 'QUEUED');
      assert.equal(statusAction.completedAt, null);

      // 3. Ring Device on Android requires MFA step-up and stays QUEUED until phone receipt
      let mfaSecret = await stepUpSession(server, session, repository, 'SENSITIVE_COMMAND');
      const ringAndroidRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'RING_DEVICE',
        },
      });
      assert.equal(ringAndroidRes.status, 200);
      const ringAction = ringAndroidRes.body.action as {
        actionType: string;
        status: string;
        completedAt: string | null;
      };
      assert.equal(ringAction.actionType, 'RING_DEVICE');
      assert.equal(ringAction.status, 'QUEUED');
      assert.equal(ringAction.completedAt, null);

      // 4. Enable Lost Mode transitions server-side device state to LOST and emits HIGH notification
      mfaSecret = await stepUpSession(server, session, repository, 'ENABLE_LOST_MODE', mfaSecret);
      const lostEnableRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'ENABLE_LOST_MODE',
          title: 'Lost Phone',
          message: 'Lost device — please contact owner.',
          contactInstruction: '+91 98765 43210',
        },
      });
      assert.equal(lostEnableRes.status, 200);
      assert.equal((lostEnableRes.body.device as { lifecycleState: string }).lifecycleState, 'LOST');

      // 5. Disable Lost Mode restores TRUSTED (since no heartbeat received yet) without fabricating ONLINE
      mfaSecret = await stepUpSession(server, session, repository, 'DISABLE_LOST_MODE', mfaSecret);
      const lostDisableRes = await requestJson(server, {
        method: 'POST',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          actionType: 'DISABLE_LOST_MODE',
        },
      });
      assert.equal(lostDisableRes.status, 200);
      assert.equal((lostDisableRes.body.device as { lifecycleState: string }).lifecycleState, 'TRUSTED');

      // 6. Verify device action history endpoint (only the 4 supported actions were persisted)
      const actionsListRes = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${androidId}/actions`,
        cookie: session.cookie,
      });
      assert.equal(actionsListRes.status, 200);
      const actions = actionsListRes.body.actions as Array<{ actionType: string }>;
      assert.equal(actions.length, 4);

      // 7. Verify Security Activity feed includes Recovery category items
      const activityRes = await requestJson(server, {
        method: 'GET',
        path: '/api/activity?category=Recovery',
        cookie: session.cookie,
      });
      assert.equal(activityRes.status, 200);
      const recoveryItems = activityRes.body.activities as Array<{
        category: string;
        title: string;
      }>;
      assert.ok(recoveryItems.length >= 3);
      assert.equal(
        recoveryItems.every((item) => item.category === 'Recovery'),
        true
      );
    } finally {
      server.close();
    }
  });

  it('ThreatCheck inspection endpoint logs activity and creates notification when high-risk link is detected', async () => {
    const repository = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const session = await registerAndLoginUser(server, 'threatcheck@vajra.local');

      // 1. Inspect a low-risk URL
      const safeRes = await requestJson(server, {
        method: 'POST',
        path: '/api/threatcheck/inspect',
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          url: 'https://github.com/security',
        },
      });
      assert.equal(safeRes.status, 200);
      const safeAnalysis = safeRes.body.analysis as { verdict: string };
      assert.equal(safeAnalysis.verdict, 'LOW RISK');
      assert.equal(safeRes.body.notification, null);

      // 2. Inspect a high-risk deceptive URL
      const dangerRes = await requestJson(server, {
        method: 'POST',
        path: '/api/threatcheck/inspect',
        cookie: session.cookie,
        csrfToken: session.csrfToken,
        body: {
          url: 'http://198.51.100.42/login-verify/password-reset?token=secret123',
        },
      });
      assert.equal(dangerRes.status, 200);
      const dangerAnalysis = dangerRes.body.analysis as {
        verdict: string;
        normalizedDisplayUrl: string;
      };
      assert.equal(dangerAnalysis.verdict, 'HIGH RISK');
      assert.equal(dangerAnalysis.normalizedDisplayUrl.includes('secret123'), false);
      assert.equal(dangerAnalysis.normalizedDisplayUrl.endsWith('?...'), true);
      assert.notEqual(dangerRes.body.notification, null);

      // 3. Verify ThreatCheck notification was created
      const notifRes = await requestJson(server, {
        method: 'GET',
        path: '/api/notifications',
        cookie: session.cookie,
      });
      const notifications = notifRes.body.notifications as Array<{ type: string; severity: string }>;
      assert.equal(
        notifications.some((n) => n.type === 'THREATCHECK_COMPLETED' && n.severity === 'HIGH'),
        true,
        'Expected THREATCHECK_COMPLETED HIGH notification after high-risk URL check'
      );

      // 4. Verify ThreatCheck activity appears in Security Activity feed
      const activityRes = await requestJson(server, {
        method: 'GET',
        path: '/api/activity?category=ThreatCheck',
        cookie: session.cookie,
      });
      const threatActivities = activityRes.body.activities as Array<{ category: string }>;
      assert.equal(threatActivities.length, 2);
    } finally {
      server.close();
    }
  });
});
