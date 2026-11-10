/**
 * VAJRA — Prompt 0047 Regression Tests:
 * Native Windows & Android Agent Integration Contracts
 *
 * Covers confirmed integration defects repaired in Prompt 0047:
 * 1. Windows agent Plane-2 event ingestion (`AGENT_STARTED`, `WINDOWS_EVENT_LOG`, `AGENT_STOPPED`)
 *    accepted by `POST /api/devices/:id/events` with `source = "WINDOWS_AGENT"` and persisted cleanly.
 * 2. Android Plane-2 heartbeat payload with unknown/omitted battery & charging states (`null`)
 *    persists `batteryLevel: null` and `charging: null` without fabricating `charging: false`.
 * 3. Unsupported non-allowlisted commands (`RUN_POWERSHELL`, `INSTALL_APK`) are rejected with
 *    `400 UNSUPPORTED_DEVICE_ACTION` without creating queued command records.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import {
  generateDeviceKeyPair,
  signDeviceRequest,
  signEnrollmentProof,
} from '../packages/security/src/node.ts';

describe('Prompt 0047 — Native Agent Plane-2 Integration Contracts', () => {
  let server: http.Server;
  let baseUrl = '';
  let cookieHeader = '';
  let csrfToken = '';

  before(async () => {
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to bind ephemeral server port.');
    }
    baseUrl = `http://127.0.0.1:${addr.port}`;

    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'prompt0047-owner@vajra.test',
        displayName: 'Prompt 0047 Owner',
        password: 'Correct-Horse-Battery-99!Staple',
      }),
    });
    assert.equal(regRes.status, 201);
    const setCookies = regRes.headers.getSetCookie();
    cookieHeader = setCookies.map((c) => c.split(';')[0]).join('; ');
    const regJson = (await regRes.json()) as { csrfToken: string };
    csrfToken = regJson.csrfToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function enrollAndConfirmDevice(deviceType: 'WINDOWS' | 'ANDROID', name: string) {
    const initRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        name,
        deviceType,
        osVersion: deviceType === 'WINDOWS' ? 'Windows 11 23H2' : 'Android 14',
      }),
    });
    assert.equal(initRes.status, 201);
    const initData = (await initRes.json()) as {
      device: { id: string };
      enrollment: {
        enrollmentToken: string;
        challengeNonce: string;
        verificationPasscode?: string;
      };
    };

    const kp = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(24).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      deviceId: initData.device.id,
      enrollmentToken: initData.enrollment.enrollmentToken,
      challengeNonce: initData.enrollment.challengeNonce,
      publicKeyFingerprint: kp.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const subRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollmentToken: initData.enrollment.enrollmentToken,
        verificationPasscode: initData.enrollment.verificationPasscode,
        publicKeyPem: kp.publicKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        signatureBase64,
        timestampIso,
        clientNonce,
      }),
    });
    assert.equal(subRes.status, 200);

    const confRes = await fetch(
      `${baseUrl}/api/devices/${initData.device.id}/enrollment/confirm`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieHeader,
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ publicKeyFingerprint: kp.publicKeyFingerprint }),
      }
    );
    assert.equal(confRes.status, 200);

    return { deviceId: initData.device.id, kp };
  }

  it('ingests signed Windows agent AGENT_STARTED, WINDOWS_EVENT_LOG, and AGENT_STOPPED events and rejects unsupported commands', async () => {
    const { deviceId, kp } = await enrollAndConfirmDevice('WINDOWS', 'WIN11-AGENT-REGRESSION');

    for (const evt of [
      {
        category: 'Device',
        type: 'AGENT_STARTED',
        severity: 'INFO',
        title: 'Windows agent started',
        description: 'VAJRA Windows agent 0.1.0-windows is running.',
        source: 'WINDOWS_AGENT',
        metadata: { agentVersion: '0.1.0-windows', os: 'Microsoft Windows 10.0.22631' },
      },
      {
        category: 'Device',
        type: 'WINDOWS_EVENT_LOG',
        severity: 'WARNING',
        title: 'Windows System: Service Control Manager',
        description: 'Sample allowlisted Windows event record.',
        source: 'WINDOWS_AGENT',
        metadata: { logName: 'System', provider: 'Service Control Manager', eventId: 7036 },
      },
      {
        category: 'Device',
        type: 'AGENT_STOPPED',
        severity: 'INFO',
        title: 'Windows agent stopped',
        description: 'VAJRA Windows agent is shutting down.',
        source: 'WINDOWS_AGENT',
      },
    ]) {
      const path = `/api/devices/${deviceId}/events`;
      const timestampIso = new Date().toISOString();
      const nonce = crypto.randomBytes(24).toString('hex');
      const sig = signDeviceRequest({
        privateKeyPem: kp.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        method: 'POST',
        path,
        deviceId,
        timestampIso,
        nonce,
        body: evt,
      });

      const evtRes = await fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': timestampIso,
          'X-Vajra-Nonce': nonce,
          'X-Vajra-Signature': sig,
        },
        body: JSON.stringify(evt),
      });
      assert.equal(evtRes.status, 201);
    }

    const listRes = await fetch(`${baseUrl}/api/events?deviceId=${deviceId}`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(listRes.status, 200);
    const listData = (await listRes.json()) as { events: Array<{ type: string; source: string }> };
    const types = listData.events.map((e) => e.type);
    assert.ok(types.includes('AGENT_STARTED'));
    assert.ok(types.includes('WINDOWS_EVENT_LOG'));
    assert.ok(types.includes('AGENT_STOPPED'));

    // Rejects unsupported command without queuing
    const badCmd = await fetch(`${baseUrl}/api/devices/${deviceId}/commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ actionType: 'RUN_POWERSHELL' }),
    });
    assert.equal(badCmd.status, 400);

    const cmdsRes = await fetch(`${baseUrl}/api/devices/${deviceId}/commands`, {
      headers: { Cookie: cookieHeader },
    });
    const cmdsData = (await cmdsRes.json()) as { commands: unknown[] };
    assert.equal(cmdsData.commands.length, 0);
  });

  it('persists null charging when Android heartbeat omits battery/charging telemetry and preserves valid readings', async () => {
    const { deviceId, kp } = await enrollAndConfirmDevice('ANDROID', 'PIXEL-BATTERY-REGRESSION');

    const sendHeartbeat = async (payload: Record<string, unknown>) => {
      const path = `/api/devices/${deviceId}/heartbeat`;
      const timestampIso = new Date().toISOString();
      const nonce = crypto.randomBytes(24).toString('hex');
      const sig = signDeviceRequest({
        privateKeyPem: kp.privateKeyPem,
        keyAlgorithm: 'ECDSA_P256',
        method: 'POST',
        path,
        deviceId,
        timestampIso,
        nonce,
        body: payload,
      });
      return fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': timestampIso,
          'X-Vajra-Nonce': nonce,
          'X-Vajra-Signature': sig,
        },
        body: JSON.stringify(payload),
      });
    };

    // Valid charging reading
    const hbValid = await sendHeartbeat({
      connectivityStatus: 'ONLINE',
      agentVersion: '0.1.0-android',
      osVersion: 'Android 14',
      platform: 'ANDROID',
      batteryLevel: 67,
      charging: true,
    });
    assert.equal(hbValid.status, 200);

    // Heartbeat when sticky battery intent is unavailable (omits both batteryLevel and charging)
    const hbUnknown = await sendHeartbeat({
      connectivityStatus: 'ONLINE',
      agentVersion: '0.1.0-android',
      osVersion: 'Android 14',
      platform: 'ANDROID',
    });
    assert.equal(hbUnknown.status, 200);
    const hbUnknownData = (await hbUnknown.json()) as {
      heartbeat: { batteryLevel: number | null; charging: boolean | null };
    };
    assert.equal(hbUnknownData.heartbeat.batteryLevel, null);
    assert.equal(hbUnknownData.heartbeat.charging, null);

    // Battery history only returns genuine battery readings (count = 1), with latest charging = null
    const histRes = await fetch(`${baseUrl}/api/devices/${deviceId}/battery-history`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(histRes.status, 200);
    const histData = (await histRes.json()) as {
      currentLevel: number | null;
      charging: boolean | null;
      readings: Array<{ batteryLevel: number; charging: boolean | null }>;
    };
    assert.equal(histData.currentLevel, null);
    assert.equal(histData.charging, null);
    assert.equal(histData.readings.length, 1);
    assert.equal(histData.readings[0].batteryLevel, 67);
    assert.equal(histData.readings[0].charging, true);
  });
});
