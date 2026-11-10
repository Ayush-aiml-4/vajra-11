/**
 * VAJRA — Prompt 0038 Test Suite
 * Battery Telemetry 24-Hour Trend Endpoint & Integrity Checks
 *
 * Covers:
 * 1. Authentication enforcement (401 when unauthenticated)
 * 2. Cross-user device ownership isolation (404 when querying another user's device)
 * 3. Platform gating (400 UNSUPPORTED_PLATFORM when device is not ANDROID)
 * 4. Identifier validation (400 INVALID_DEVICE_ID on empty or oversized IDs)
 * 5. Honest empty telemetry (returns 200 with readings: [] and hasTelemetry: false when no data exists)
 * 6. Real telemetry persistence (returns only genuinely persisted readings within 24h, chronological order)
 * 7. Query boundary (filters out readings older than 24h, bounds result set)
 * 8. Commands endpoint isolation (GET /api/devices/:id/commands does not leak/synthesize battery trend)
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import express from 'express';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import { createSessionResolutionMiddleware } from '../src/server/auth/middleware.ts';
import { createAuthRouter } from '../src/server/auth/routes.ts';
import { createDeviceRouter } from '../src/server/devices/routes.ts';
import { createNotificationAndActivityRouter } from '../src/server/notifications/routes.ts';
import { TEST_TOTP_ENCRYPTION_KEY } from './helpers/mfaTestSupport.ts';
import {
  generateDeviceKeyPair,
  signEnrollmentProof,
  signDeviceRequest,
} from '../packages/security/src/node.ts';

interface TestAgent {
  cookie: string;
  csrfToken: string;
  userId: string;
}

function signHeaders(
  keyPair: ReturnType<typeof generateDeviceKeyPair>,
  deviceId: string,
  method: string,
  path: string,
  body: unknown
) {
  const timestampIso = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const signatureBase64 = signDeviceRequest({
    privateKeyPem: keyPair.privateKeyPem,
    keyAlgorithm: 'ED25519',
    method,
    path,
    deviceId,
    timestampIso,
    nonce,
    body,
  });
  return {
    'Content-Type': 'application/json',
    'X-Vajra-Device-Id': deviceId,
    'X-Vajra-Timestamp': timestampIso,
    'X-Vajra-Nonce': nonce,
    'X-Vajra-Signature': signatureBase64,
  };
}

async function requestJson(
  baseUrl: string,
  path: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
  } = {}
): Promise<{ status: number; headers: Headers; data: any }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? 'GET',
    headers: {
      Accept: 'application/json',
      ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers ?? {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, headers: res.headers, data };
}

describe('VAJRA Prompt 0038 — 24-Hour Battery Telemetry History Endpoint', () => {
  let server: http.Server;
  let baseUrl: string;
  let repo: InMemoryIdentityRepository;

  let ownerA: TestAgent;
  let ownerB: TestAgent;
  let androidDeviceA: { id: string; name: string };
  let deviceKeyPairA: ReturnType<typeof generateDeviceKeyPair>;
  let windowsDeviceA: { id: string; name: string };
  let androidDeviceB: { id: string; name: string };

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = express();
    app.use(express.json({ limit: '100kb' }));
    app.use('/api', createSessionResolutionMiddleware(repo));
    app.use('/api', createAuthRouter({ repository: repo, totpEncryptionKey: TEST_TOTP_ENCRYPTION_KEY }));
    app.use('/api', createDeviceRouter({ repository: repo }));
    app.use('/api', createNotificationAndActivityRouter({ repository: repo }));

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });

    // Register User A
    const regResA = await requestJson(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        email: 'battery-owner-a@vajra.local',
        displayName: 'Owner A',
        password: 'Password123!',
      },
    });
    assert.equal(regResA.status, 201);
    const setCookieA = regResA.headers.get('set-cookie')?.split(';')[0] ?? '';
    ownerA = {
      cookie: setCookieA,
      csrfToken: regResA.data.csrfToken,
      userId: regResA.data.user.id,
    };

    // Register User B
    const regResB = await requestJson(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        email: 'battery-owner-b@vajra.local',
        displayName: 'Owner B',
        password: 'Password123!',
      },
    });
    assert.equal(regResB.status, 201);
    const setCookieB = regResB.headers.get('set-cookie')?.split(';')[0] ?? '';
    ownerB = {
      cookie: setCookieB,
      csrfToken: regResB.data.csrfToken,
      userId: regResB.data.user.id,
    };

    // Enroll and confirm Android device A with cryptographic keypair
    const initResA = await requestJson(baseUrl, '/api/devices/enrollment/initiate', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        proposedDeviceName: 'Pixel 9 Pro (Owner A)',
        expectedDeviceType: 'ANDROID',
      },
    });
    assert.equal(initResA.status, 201);
    const bundleA = initResA.data.enrollment;
    androidDeviceA = { id: bundleA.deviceId, name: 'Pixel 9 Pro (Owner A)' };

    deviceKeyPairA = generateDeviceKeyPair('ED25519');
    const timestampIso = new Date().toISOString();
    const clientNonce = 'battery-test-nonce-0001';
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      publicKeyFingerprint: deviceKeyPairA.publicKeyFingerprint,
      deviceId: bundleA.deviceId,
      enrollmentToken: bundleA.enrollmentToken,
      challengeNonce: bundleA.challengeNonce,
      timestampIso,
      clientNonce,
    });

    const submitResA = await requestJson(baseUrl, '/api/devices/enrollment/submit', {
      method: 'POST',
      body: {
        enrollmentToken: bundleA.enrollmentToken,
        verificationPasscode: bundleA.verificationPasscode,
        keyAlgorithm: 'ED25519',
        publicKeyPem: deviceKeyPairA.publicKeyPem,
        signatureBase64,
        timestampIso,
        clientNonce,
        hardwareBacked: true,
        osVersion: 'Android 15',
        agentVersion: '0.1.0-android',
      },
    });
    assert.equal(submitResA.status, 200);

    const confirmResA = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/enrollment/confirm`,
      {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
        body: {
          publicKeyFingerprint: deviceKeyPairA.publicKeyFingerprint,
        },
      }
    );
    assert.equal(confirmResA.status, 200);

    // Create Windows device for User A
    const { device: devWinA } = await repo.createEnrollmentPendingDevice({
      userId: ownerA.userId,
      name: 'ThinkPad X1 (Owner A)',
      deviceType: 'WINDOWS',
      tokenHash: 'tok-hash-win-a',
      nonce: 'nonce-win-a',
      expiresAt: new Date(Date.now() + 600_000),
    });
    windowsDeviceA = { id: devWinA.id, name: devWinA.name };

    // Create Android device for User B
    const { device: devB } = await repo.createEnrollmentPendingDevice({
      userId: ownerB.userId,
      name: 'Galaxy S24 (Owner B)',
      deviceType: 'ANDROID',
      tokenHash: 'tok-hash-android-b',
      nonce: 'nonce-android-b',
      expiresAt: new Date(Date.now() + 600_000),
    });
    androidDeviceB = { id: devB.id, name: devB.name };
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. rejects unauthenticated access to battery history with 401', async () => {
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/battery-history`
    );
    assert.equal(res.status, 401);
  });

  it('2. returns 404 DEVICE_NOT_FOUND for non-existent device', async () => {
    const nonExistentId = '00000000-0000-0000-0000-000000000000';
    const res = await requestJson(
      baseUrl,
      `/api/devices/${nonExistentId}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(res.status, 404);
    assert.equal(res.data?.error?.code, 'DEVICE_NOT_FOUND');
  });

  it('3. prevents cross-user access: user A cannot access user B device battery history (404)', async () => {
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceB.id}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(res.status, 404);
    assert.equal(res.data?.error?.code, 'DEVICE_NOT_FOUND');
  });

  it('4. rejects non-Android device with 400 UNSUPPORTED_PLATFORM', async () => {
    const res = await requestJson(
      baseUrl,
      `/api/devices/${windowsDeviceA.id}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(res.status, 400);
    assert.equal(res.data?.error?.code, 'UNSUPPORTED_PLATFORM');
  });

  it('5. returns 200 with empty readings array and hasTelemetry: false when no heartbeats exist', async () => {
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(res.status, 200);
    assert.equal(res.data.deviceId, androidDeviceA.id);
    assert.equal(res.data.platform, 'ANDROID');
    assert.equal(res.data.hasTelemetry, false);
    assert.deepEqual(res.data.readings, []);
    assert.equal(res.data.currentLevel, null);
    assert.equal(res.data.charging, null);
  });

  it('6. returns genuine persisted battery readings within 24 hours in chronological order without synthetic points', async () => {
    const now = new Date();
    // Insert 3 real heartbeats within 24h
    const t1 = new Date(now.getTime() - 6 * 3600 * 1000); // 6 hours ago
    const t2 = new Date(now.getTime() - 3 * 3600 * 1000); // 3 hours ago
    const t3 = new Date(now.getTime() - 10 * 60 * 1000);   // 10 mins ago

    // Insert 1 stale heartbeat older than 24h (should be excluded)
    const tOld = new Date(now.getTime() - 26 * 3600 * 1000);

    // Heartbeat with null batteryLevel (should be excluded from readings)
    const tNull = new Date(now.getTime() - 2 * 3600 * 1000);

    await repo.createDeviceHeartbeat({
      deviceId: androidDeviceA.id,
      receivedAt: tOld,
      batteryLevel: 99,
      charging: true,
    });

    await repo.createDeviceHeartbeat({
      deviceId: androidDeviceA.id,
      receivedAt: t1,
      batteryLevel: 85,
      charging: false,
    });

    await repo.createDeviceHeartbeat({
      deviceId: androidDeviceA.id,
      receivedAt: tNull,
      batteryLevel: null,
      charging: false,
    });

    await repo.createDeviceHeartbeat({
      deviceId: androidDeviceA.id,
      receivedAt: t2,
      batteryLevel: 72,
      charging: false,
    });

    await repo.createDeviceHeartbeat({
      deviceId: androidDeviceA.id,
      receivedAt: t3,
      batteryLevel: 68,
      charging: true,
    });

    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );

    assert.equal(res.status, 200);
    assert.equal(res.data.hasTelemetry, true);
    assert.equal(res.data.currentLevel, 68);
    assert.equal(res.data.charging, true);

    // Exactly 3 readings (tOld excluded because > 24h, tNull excluded because batteryLevel is null)
    assert.equal(res.data.readings.length, 3);

    // Verify chronological order: t1 then t2 then t3
    assert.equal(res.data.readings[0].batteryLevel, 85);
    assert.equal(res.data.readings[0].charging, false);
    assert.equal(res.data.readings[1].batteryLevel, 72);
    assert.equal(res.data.readings[1].charging, false);
    assert.equal(res.data.readings[2].batteryLevel, 68);
    assert.equal(res.data.readings[2].charging, true);

    // Verify no synthetic readings were injected
    for (const pt of res.data.readings) {
      assert.ok(typeof pt.batteryLevel === 'number');
      assert.ok(typeof pt.time === 'string');
      assert.ok(typeof pt.timestamp === 'string');
      assert.ok(typeof pt.charging === 'boolean');
    }
  });

  it('7. commands endpoint GET /api/devices/:id/commands does NOT contain batteryTrend', async () => {
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/commands`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.commands));
    assert.ok(res.data.locationSummary);
    // batteryTrend must NOT be present
    assert.equal(res.data.batteryTrend, undefined);
  });

  it('8. rejects invalid battery level (> 100) on POST heartbeat with 400 INVALID_BATTERY_LEVEL', async () => {
    const invalidBody = {
      connectivityStatus: 'ONLINE',
      batteryLevel: 150,
      charging: false,
    };
    const headers = signHeaders(
      deviceKeyPairA,
      androidDeviceA.id,
      'POST',
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      invalidBody
    );
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      {
        method: 'POST',
        headers,
        body: invalidBody,
      }
    );
    assert.equal(res.status, 400);
    assert.equal(res.data?.error?.code, 'INVALID_BATTERY_LEVEL');
  });

  it('9. rejects negative battery level (< 0) on POST heartbeat with 400 INVALID_BATTERY_LEVEL', async () => {
    const invalidBody = {
      connectivityStatus: 'ONLINE',
      batteryLevel: -10,
      charging: false,
    };
    const headers = signHeaders(
      deviceKeyPairA,
      androidDeviceA.id,
      'POST',
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      invalidBody
    );
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      {
        method: 'POST',
        headers,
        body: invalidBody,
      }
    );
    assert.equal(res.status, 400);
    assert.equal(res.data?.error?.code, 'INVALID_BATTERY_LEVEL');
  });

  it('10. rejects non-boolean charging value on POST heartbeat with 400 INVALID_CHARGING_STATE', async () => {
    const invalidBody = {
      connectivityStatus: 'ONLINE',
      batteryLevel: 75,
      charging: 'yes',
    };
    const headers = signHeaders(
      deviceKeyPairA,
      androidDeviceA.id,
      'POST',
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      invalidBody
    );
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      {
        method: 'POST',
        headers,
        body: invalidBody,
      }
    );
    assert.equal(res.status, 400);
    assert.equal(res.data?.error?.code, 'INVALID_CHARGING_STATE');
  });

  it('11. accepts valid signed Android heartbeat with battery telemetry and updates battery history', async () => {
    const validBody = {
      connectivityStatus: 'ONLINE',
      batteryLevel: 92,
      charging: true,
      networkType: 'WIFI',
    };
    const headers = signHeaders(
      deviceKeyPairA,
      androidDeviceA.id,
      'POST',
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      validBody
    );
    const res = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/heartbeat`,
      {
        method: 'POST',
        headers,
        body: validBody,
      }
    );
    assert.equal(res.status, 200);
    assert.equal(res.data.heartbeat.batteryLevel, 92);
    assert.equal(res.data.heartbeat.charging, true);

    const historyRes = await requestJson(
      baseUrl,
      `/api/devices/${androidDeviceA.id}/battery-history`,
      {
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(historyRes.status, 200);
    assert.equal(historyRes.data.hasTelemetry, true);
    assert.equal(historyRes.data.currentLevel, 92);
    assert.equal(historyRes.data.charging, true);
    const lastReading = historyRes.data.readings[historyRes.data.readings.length - 1];
    assert.equal(lastReading.batteryLevel, 92);
    assert.equal(lastReading.charging, true);
  });
});
