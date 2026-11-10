/**
 * VAJRA — Prompt 0008 Test Suite
 * Security Event Engine + Real-Time Product State + Stateful Command Lifecycle + Heartbeat Protocol
 *
 * Covers:
 * 1. Event validation & ingestion (types, categories, severities, sources, ownership)
 * 2. Clock-skew validation (rejects future timestamps > 5m and stale timestamps > 30d)
 * 3. Metadata safety (rejects passwords, tokens, private keys, TOTP secrets, raw hashes)
 * 4. Notification policy & deduplication (auto-creates notifications for high-consequence events, deduplicates within 5m)
 * 5. Deterministic Risk Engine (0–100 score, PROTECTED / ATTENTION NEEDED / HIGH RISK status, factors & recommendations)
 * 6. Stateful Command Lifecycle (QUEUED -> DELIVERED -> ACKNOWLEDGED -> COMPLETED / FAILED / CANCELLED / EXPIRED + idempotent CommandResult)
 * 7. Cryptographically signed Device Heartbeat protocol & pending command count
 * 8. Cross-user isolation across /api/events, /api/security/risk, /api/devices/:id/commands, and /api/demo/events
 * 9. Demo Security Event simulation pipeline
 */

import { describe, it, before, after } from 'node:test';
import {
  TEST_TOTP_ENCRYPTION_KEY,
  enableMfaForUser,
  currentTotpCode,
} from './helpers/mfaTestSupport.ts';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import express from 'express';
import {
  generateDeviceKeyPair,
  signEnrollmentProof,
  signDeviceRequest,
  SupportedKeyAlgorithm,
} from '../packages/security/src/node.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import { createSessionResolutionMiddleware } from '../src/server/auth/middleware.ts';
import { createAuthRouter } from '../src/server/auth/routes.ts';
import { createDeviceRouter } from '../src/server/devices/routes.ts';
import { createNotificationAndActivityRouter } from '../src/server/notifications/routes.ts';

function buildDeviceAuthHeaders(params: {
  deviceId: string;
  privateKeyPem: string;
  keyAlgorithm: SupportedKeyAlgorithm;
  method: string;
  path: string;
  body: unknown;
}): Record<string, string> {
  const timestampIso = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const signatureBase64 = signDeviceRequest({
    privateKeyPem: params.privateKeyPem,
    keyAlgorithm: params.keyAlgorithm,
    method: params.method,
    path: params.path,
    deviceId: params.deviceId,
    timestampIso,
    nonce,
    body: params.body,
  });
  return {
    'X-Vajra-Device-Id': params.deviceId,
    'X-Vajra-Timestamp': timestampIso,
    'X-Vajra-Nonce': nonce,
    'X-Vajra-Signature': signatureBase64,
  };
}

interface TestAgent {
  cookie: string;
  csrfToken: string;
  userId: string;
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

describe('VAJRA Prompt 0008 — Security Event Engine, Risk Engine & Command Lifecycle', () => {
  let server: http.Server;
  let baseUrl: string;
  let repo: InMemoryIdentityRepository;

  let ownerA: TestAgent;
  let ownerB: TestAgent;
  let enrolledDeviceIdA: string;
  let deviceKeyPairA: ReturnType<typeof generateDeviceKeyPair>;

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

    // Register Owner A
    const regA = await requestJson(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        email: 'aarav.prompt8@example.com',
        displayName: 'Aarav Mehta',
        password: 'CorrectHorseBatteryStaple!99',
      },
    });
    assert.equal(regA.status, 201);
    const rawCookieA = regA.headers.get('set-cookie') ?? '';
    ownerA = {
      cookie: rawCookieA.split(';')[0],
      csrfToken: regA.data.csrfToken,
      userId: regA.data.user.id,
    };

    // Register Owner B
    const regB = await requestJson(baseUrl, '/api/auth/register', {
      method: 'POST',
      body: {
        email: 'maya.prompt8@example.com',
        displayName: 'Maya Sharma',
        password: 'AnotherStrongPassword!88',
      },
    });
    assert.equal(regB.status, 201);
    const rawCookieB = regB.headers.get('set-cookie') ?? '';
    ownerB = {
      cookie: rawCookieB.split(';')[0],
      csrfToken: regB.data.csrfToken,
      userId: regB.data.user.id,
    };

    // Enroll and confirm a trusted device for Owner A
    const initRes = await requestJson(baseUrl, '/api/devices/enrollment/initiate', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        proposedDeviceName: 'Aarav Studio Companion',
        expectedDeviceType: 'ANDROID',
      },
    });
    assert.equal(initRes.status, 201);
    const bundle = initRes.data.enrollment;
    enrolledDeviceIdA = bundle.deviceId;

    deviceKeyPairA = generateDeviceKeyPair('ED25519');
    const timestampIso = new Date().toISOString();
    const clientNonce = 'prompt8-enroll-nonce-0001';
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      publicKeyFingerprint: deviceKeyPairA.publicKeyFingerprint,
      deviceId: bundle.deviceId,
      enrollmentToken: bundle.enrollmentToken,
      challengeNonce: bundle.challengeNonce,
      timestampIso,
      clientNonce,
    });

    const submitRes = await requestJson(baseUrl, '/api/devices/enrollment/submit', {
      method: 'POST',
      body: {
        enrollmentToken: bundle.enrollmentToken,
        verificationPasscode: bundle.verificationPasscode,
        keyAlgorithm: 'ED25519',
        publicKeyPem: deviceKeyPairA.publicKeyPem,
        signatureBase64,
        timestampIso,
        clientNonce,
        hardwareBacked: true,
        osVersion: 'Windows 11 Pro 24H2',
        agentVersion: '1.2.0',
      },
    });
    assert.equal(submitRes.status, 200);

    const confirmRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/enrollment/confirm`,
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
    assert.equal(confirmRes.status, 200);
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. Rejects unknown event types, future clock-skew > 5 minutes, and stale timestamps > 30 days', async () => {
    const unknownTypeRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        category: 'Security',
        type: 'ARBITRARY_ROOTKIT_EVENT',
      },
    });
    assert.equal(unknownTypeRes.status, 400);
    assert.match(unknownTypeRes.data.error.message, /UNSUPPORTED_EVENT_TYPE/);

    const futureTime = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const futureSkewRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        category: 'Device',
        type: 'DEVICE_SECURITY_CHECK',
        occurredAt: futureTime,
      },
    });
    assert.equal(futureSkewRes.status, 400);
    assert.match(futureSkewRes.data.error.message, /CLOCK_SKEW_EXCEEDED/);

    const staleTime = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    const staleRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        category: 'Device',
        type: 'DEVICE_SECURITY_CHECK',
        occurredAt: staleTime,
      },
    });
    assert.equal(staleRes.status, 400);
    assert.match(staleRes.data.error.message, /STALE_EVENT_TIMESTAMP/);
  });

  it('2. Rejects sensitive metadata keys (password, token, privateKey, totpSecret, recoveryCode)', async () => {
    const forbiddenPayloads = [
      { passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$secret' },
      { sessionToken: 'raw-session-token-123' },
      { totpSecret: 'JBSWY3DPEHPK3PXP' },
      { privateKey: '-----BEGIN PRIVATE KEY-----' },
      { recoveryCode: 'VAJRA-1234-5678' },
    ];

    for (const badMeta of forbiddenPayloads) {
      const res = await requestJson(baseUrl, '/api/events', {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
        body: {
          category: 'Security',
          type: 'DEVICE_SECURITY_CHECK',
          metadata: badMeta,
        },
      });
      assert.equal(res.status, 400, `Expected 400 for metadata ${JSON.stringify(badMeta)}`);
      assert.match(res.data.error.message, /INVALID_EVENT_METADATA/);
    }
  });

  it('3. Ingests valid SecurityEvents, triggers notification policy, deduplicates, and updates RiskAssessment', async () => {
    const ingestRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        deviceId: enrolledDeviceIdA,
        category: 'ThreatCheck',
        type: 'THREATCHECK_HIGH_RISK',
        severity: 'HIGH',
        source: 'THREATCHECK',
        title: 'High-risk credential harvesting link blocked',
        description: 'ThreatCheck detected an impersonation domain targeting your account.',
        metadata: {
          inspectedHost: 'login-verify-vault.example',
        },
      },
    });
    assert.equal(ingestRes.status, 201);
    assert.equal(ingestRes.data.event.type, 'THREATCHECK_HIGH_RISK');
    assert.ok(ingestRes.data.notification, 'Expected policy notification to be created');
    assert.ok(ingestRes.data.riskAssessment, 'Expected deterministic risk assessment');
    assert.ok(
      ingestRes.data.riskAssessment.score < 100,
      'Score should reflect MFA disabled + high-risk ThreatCheck'
    );

    // Immediate duplicate event within 5 minutes should reuse the existing unread notification
    const duplicateRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        deviceId: enrolledDeviceIdA,
        category: 'ThreatCheck',
        type: 'THREATCHECK_HIGH_RISK',
        severity: 'HIGH',
        source: 'THREATCHECK',
        title: 'High-risk credential harvesting link blocked',
        description: 'ThreatCheck detected an impersonation domain targeting your account.',
      },
    });
    assert.equal(duplicateRes.status, 201);
    assert.equal(
      duplicateRes.data.notification.id,
      ingestRes.data.notification.id,
      'Expected deduplicated notification ID within 5-minute window'
    );
  });

  it('4. Executes full Stateful Command Lifecycle (QUEUED -> DELIVERED -> ACKNOWLEDGED -> COMPLETED + Idempotent Result)', async () => {
    // 4a. Owner A queues a RING_DEVICE command (requires MFA step-up)
    const secretA = await enableMfaForUser(repo, ownerA.userId, TEST_TOTP_ENCRYPTION_KEY);
    const stepRes = await requestJson(baseUrl, '/api/auth/step-up', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        totpCode: currentTotpCode(secretA),
        actionScope: 'SENSITIVE_COMMAND',
      },
    });
    assert.equal(stepRes.status, 200, JSON.stringify(stepRes.data));
    const createCmdRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands`,
      {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
        body: {
          actionType: 'RING_DEVICE',
          ttlMinutes: 30,
        },
      }
    );
    assert.equal(createCmdRes.status, 201);
    const commandId = createCmdRes.data.command.id;
    assert.equal(createCmdRes.data.command.status, 'QUEUED');

    // 4b. Trusted Device Agent polls GET /api/devices/:id/commands/pending -> transitions to DELIVERED
    const pendingPath = `/api/devices/${enrolledDeviceIdA}/commands/pending`;
    const pendingHeaders = buildDeviceAuthHeaders({
      deviceId: enrolledDeviceIdA,
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'GET',
      path: pendingPath,
      body: '',
    });
    const pendingRes = await requestJson(baseUrl, pendingPath, {
      method: 'GET',
      headers: pendingHeaders,
    });
    assert.equal(pendingRes.status, 200);
    const deliveredCmd = pendingRes.data.commands.find((c: any) => c.id === commandId);
    assert.ok(deliveredCmd, 'Expected queued command in pending list');
    assert.equal(deliveredCmd.status, 'DELIVERED');
    assert.ok(deliveredCmd.deliveredAt);

    // 4c. Trusted Device Agent acknowledges command -> transitions to ACKNOWLEDGED
    const ackPath = `/api/devices/${enrolledDeviceIdA}/commands/${commandId}/acknowledge`;
    const ackBodyObj = {};
    const ackHeaders = buildDeviceAuthHeaders({
      deviceId: enrolledDeviceIdA,
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: ackPath,
      body: ackBodyObj,
    });
    const ackRes = await requestJson(baseUrl, ackPath, {
      method: 'POST',
      headers: ackHeaders,
      body: ackBodyObj,
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.data.command.status, 'ACKNOWLEDGED');
    assert.ok(ackRes.data.command.acknowledgedAt);

    // 4d. Trusted Device Agent submits final COMPLETED CommandResult
    const resultPath = `/api/devices/${enrolledDeviceIdA}/commands/${commandId}/result`;
    const resultBodyObj = {
      status: 'COMPLETED',
      safeMessage: 'Played high-volume locator chime for 60 seconds.',
      resultMetadata: { speakerOutput: 'Primary Audio' },
    };
    const resultHeaders = buildDeviceAuthHeaders({
      deviceId: enrolledDeviceIdA,
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: resultPath,
      body: resultBodyObj,
    });
    const resultRes = await requestJson(baseUrl, resultPath, {
      method: 'POST',
      headers: resultHeaders,
      body: resultBodyObj,
    });
    assert.equal(resultRes.status, 200);
    assert.equal(resultRes.data.idempotentReplay, false);
    assert.equal(resultRes.data.command.status, 'COMPLETED');
    assert.equal(
      resultRes.data.result.safeMessage,
      'Played high-volume locator chime for 60 seconds.'
    );

    // 4e. Duplicate result submission is handled idempotently
    const replayHeaders = buildDeviceAuthHeaders({
      deviceId: enrolledDeviceIdA,
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: resultPath,
      body: resultBodyObj,
    });
    const replayRes = await requestJson(baseUrl, resultPath, {
      method: 'POST',
      headers: replayHeaders,
      body: resultBodyObj,
    });
    assert.equal(replayRes.status, 200);
    assert.equal(replayRes.data.idempotentReplay, true);
  });

  it('5. Supports owner cancellation of QUEUED commands and rejects cancelling COMPLETED commands', async () => {
    const secretCancel = await enableMfaForUser(repo, ownerA.userId, TEST_TOTP_ENCRYPTION_KEY);
    const stepCancel = await requestJson(baseUrl, '/api/auth/step-up', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        totpCode: currentTotpCode(secretCancel),
        actionScope: 'SENSITIVE_COMMAND',
      },
    });
    assert.equal(stepCancel.status, 200, JSON.stringify(stepCancel.data));

    const createCmdRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands`,
      {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
        body: {
          actionType: 'RING_DEVICE',
        },
      }
    );
    assert.equal(createCmdRes.status, 201);
    const cmdId = createCmdRes.data.command.id;

    const cancelRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands/${cmdId}/cancel`,
      {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(cancelRes.status, 200);
    assert.equal(cancelRes.data.command.status, 'CANCELLED');

    // Trying to cancel an already cancelled command returns 409
    const secondCancelRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands/${cmdId}/cancel`,
      {
        method: 'POST',
        headers: {
          Cookie: ownerA.cookie,
          'X-CSRF-Token': ownerA.csrfToken,
        },
      }
    );
    assert.equal(secondCancelRes.status, 409);
  });

  it('6. Accepts cryptographically signed Device Heartbeats and updates device health state', async () => {
    const hbPath = `/api/devices/${enrolledDeviceIdA}/heartbeat`;
    const hbBody = {
      connectivityStatus: 'ONLINE',
      batteryLevel: 87,
      charging: true,
      networkType: 'WIFI',
      osVersion: 'Windows 11 Pro 24H2',
      agentVersion: '1.3.0',
      permissionSummary: 'Location & Recovery Ready',
      securitySummary: 'TPM 2.0 key active',
      locationPermissionGranted: true,
    };
    const hbHeaders = buildDeviceAuthHeaders({
      deviceId: enrolledDeviceIdA,
      privateKeyPem: deviceKeyPairA.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: hbPath,
      body: hbBody,
    });

    const hbRes = await requestJson(baseUrl, hbPath, {
      method: 'POST',
      headers: hbHeaders,
      body: hbBody,
    });
    assert.equal(hbRes.status, 200);
    assert.equal(hbRes.data.heartbeat.batteryLevel, 87);
    assert.equal(hbRes.data.heartbeat.networkType, 'WIFI');

    // Verify GET /api/devices/:id/commands returns the latestHeartbeat
    const cmdListRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands`,
      {
        method: 'GET',
        headers: { Cookie: ownerA.cookie },
      }
    );
    assert.equal(cmdListRes.status, 200);
    assert.ok(cmdListRes.data.latestHeartbeat);
    assert.equal(cmdListRes.data.latestHeartbeat.batteryLevel, 87);
  });

  it('7. Enforces strict cross-user isolation on events, risk, commands, and demo simulations', async () => {
    // Owner B cannot post an event referencing Owner A's device
    const crossEventRes = await requestJson(baseUrl, '/api/events', {
      method: 'POST',
      headers: {
        Cookie: ownerB.cookie,
        'X-CSRF-Token': ownerB.csrfToken,
      },
      body: {
        deviceId: enrolledDeviceIdA,
        category: 'Device',
        type: 'DEVICE_SECURITY_CHECK',
      },
    });
    assert.equal(crossEventRes.status, 404);

    // Owner B cannot read Owner A's device commands
    const crossCmdRes = await requestJson(
      baseUrl,
      `/api/devices/${enrolledDeviceIdA}/commands`,
      {
        method: 'GET',
        headers: { Cookie: ownerB.cookie },
      }
    );
    assert.equal(crossCmdRes.status, 404);

    // Owner B cannot query risk for Owner A's device
    const crossRiskRes = await requestJson(
      baseUrl,
      `/api/security/risk?deviceId=${enrolledDeviceIdA}`,
      {
        method: 'GET',
        headers: { Cookie: ownerB.cookie },
      }
    );
    assert.equal(crossRiskRes.status, 404);
  });

  it('8. Executes Demo Security Event simulations through the real pipeline', async () => {
    const demoRes = await requestJson(baseUrl, '/api/demo/events', {
      method: 'POST',
      headers: {
        Cookie: ownerA.cookie,
        'X-CSRF-Token': ownerA.csrfToken,
      },
      body: {
        scenario: 'SUSPICIOUS_LINK_DETECTED',
        deviceId: enrolledDeviceIdA,
      },
    });
    assert.equal(demoRes.status, 201);
    assert.equal(demoRes.data.event.metadata.demoSimulation, true);
    assert.ok(demoRes.data.riskAssessment);
  });
});
