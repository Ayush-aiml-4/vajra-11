/**
 * VAJRA — Prompt 0048 Targeted Implementation Completeness Tests
 *
 * Covers the product, protocol, security, and operational gaps closed in Prompt 0048:
 * 1. Active browser session listing (`GET /api/auth/sessions`) & individual session revocation
 *    (`POST /api/auth/sessions/:sessionId/revoke`) with cross-user isolation and zero hash leakage.
 * 2. Dedicated tamper-evident SHA-256 audit chain verification (`GET` & `POST /api/audit/verify`),
 *    including `actorDeviceId` hash-chain integrity in `InMemoryIdentityRepository`.
 * 3. Signed `POST /api/devices/:id/heartbeat` advancing `Device` posture (`TRUSTED` -> `ACTIVE`,
 *    `ONLINE`, `lastHeartbeatAt`, `osVersion`, `agentVersion`, `currentRiskScore`) and truthful
 *    device location status (no fabricated `Within ~25m` or `simulator: true` metadata).
 * 4. Safe `409 COMMAND_NOT_CANCELLABLE` response when cancelling an `ACKNOWLEDGED` command and
 *    `409` blocking of actions/commands targeting a `COMPROMISED` device.
 * 5. Production config fail-closed gates (`APP_PUBLIC_ORIGIN` HTTPS enforcement, `REQUIRE_PUBLIC_ORIGIN`,
 *    and `DATABASE_SSL_REQUIRED`).
 * 6. Presence and placeholder-only safety of operational, native-service, and Azure IaC templates.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import { validateRuntimeConfig } from '../packages/config/src/index.ts';
import {
  generateDeviceKeyPair,
  generateTotpCodeAtTime,
  signDeviceRequest,
  signEnrollmentProof,
} from '../packages/security/src/node.ts';

describe('Prompt 0048 — Full Product Implementation Closure', () => {
  let server: http.Server;
  let repo: InMemoryIdentityRepository;
  let baseUrl = '';

  let ownerCookie = '';
  let ownerCsrf = '';
  let ownerTotpSecret = '';

  let secondaryOwnerCookie = '';
  let secondaryOwnerCsrf = '';
  let secondarySessionId = '';

  let otherUserCookie = '';
  let otherUserCsrf = '';

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to bind ephemeral server port.');
    }
    baseUrl = `http://127.0.0.1:${addr.port}`;

    // 1. Register primary owner (Session #1)
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'prompt0048-owner@vajra.test',
        displayName: 'Prompt 0048 Owner',
        password: 'Correct-Horse-Battery-99!Staple',
      }),
    });
    assert.equal(regRes.status, 201);
    ownerCookie = regRes.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ');
    const regBody = (await regRes.json()) as { csrfToken: string };
    ownerCsrf = regBody.csrfToken;

    // Enroll MFA so we can exercise step-up protected commands & COMPROMISED transitions
    const mfaSetupRes = await fetch(`${baseUrl}/api/auth/mfa/setup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
    });
    assert.equal(mfaSetupRes.status, 200);
    const rotatedSetupCsrf = mfaSetupRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedSetupCsrf) ownerCsrf = rotatedSetupCsrf;
    const mfaSetupBody = (await mfaSetupRes.json()) as { secretBase32: string };
    ownerTotpSecret = mfaSetupBody.secretBase32;

    const mfaVerifyRes = await fetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({ code: generateTotpCodeAtTime(ownerTotpSecret) }),
    });
    assert.equal(mfaVerifyRes.status, 200);
    const rotatedMfaCsrf = mfaVerifyRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedMfaCsrf) ownerCsrf = rotatedMfaCsrf;

    // 2. Open a second browser session for the same owner (Session #2)
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'VAJRA-Secondary-Browser/1.0',
      },
      body: JSON.stringify({
        email: 'prompt0048-owner@vajra.test',
        password: 'Correct-Horse-Battery-99!Staple',
        totpCode: generateTotpCodeAtTime(ownerTotpSecret),
      }),
    });
    assert.equal(loginRes.status, 200);
    secondaryOwnerCookie = loginRes.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ');
    const loginBody = (await loginRes.json()) as { csrfToken?: string };
    secondaryOwnerCsrf = loginBody.csrfToken ?? '';

    // 3. Register an unrelated second user for cross-user isolation tests
    const otherRegRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'prompt0048-other@vajra.test',
        displayName: 'Other User',
        password: 'Another-Strong-Password-88!Key',
      }),
    });
    assert.equal(otherRegRes.status, 201);
    otherUserCookie = otherRegRes.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ');
    const otherBody = (await otherRegRes.json()) as { csrfToken: string };
    otherUserCsrf = otherBody.csrfToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function grantOwnerStepUp(actionScope: string) {
    const res = await fetch(`${baseUrl}/api/auth/step-up`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({
        totpCode: generateTotpCodeAtTime(ownerTotpSecret),
        actionScope,
      }),
    });
    assert.equal(res.status, 200);
    const rotated = res.headers.get('X-Vajra-Csrf-Token');
    if (rotated) ownerCsrf = rotated;
  }

  async function enrollConfirmedDevice(deviceType: 'WINDOWS' | 'ANDROID', name: string) {
    const initRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({
        name,
        deviceType,
        osVersion: deviceType === 'WINDOWS' ? 'Windows 11 23H2' : 'Android 14',
      }),
    });
    assert.equal(initRes.status, 201);
    const rotatedInit = initRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedInit) ownerCsrf = rotatedInit;
    const initData = (await initRes.json()) as {
      device: { id: string };
      enrollment: { enrollmentToken: string; challengeNonce: string; verificationPasscode?: string };
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
          Cookie: ownerCookie,
          'X-CSRF-Token': ownerCsrf,
        },
        body: JSON.stringify({ publicKeyFingerprint: kp.publicKeyFingerprint }),
      }
    );
    assert.equal(confRes.status, 200);
    const rotatedConf = confRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedConf) ownerCsrf = rotatedConf;

    return { deviceId: initData.device.id, keyPair: kp };
  }

  it('lists active sessions without token hashes, blocks cross-user revocation, and revokes an individual session cleanly', async () => {
    const listRes = await fetch(`${baseUrl}/api/auth/sessions`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(listRes.status, 200);
    const listJson = (await listRes.json()) as {
      sessions: Array<
        Record<string, unknown> & { id: string; isCurrent: boolean; userAgentSummary: string | null }
      >;
    };
    assert.equal(listJson.sessions.length, 2);
    const currentSessions = listJson.sessions.filter((s) => s.isCurrent);
    assert.equal(currentSessions.length, 1);

    for (const s of listJson.sessions) {
      assert.equal('sessionTokenHash' in s, false);
      assert.equal('csrfTokenHash' in s, false);
      assert.equal('tokenHash' in s, false);
    }

    const secondary = listJson.sessions.find((s) => !s.isCurrent);
    assert.ok(secondary, 'Expected secondary non-current session');
    secondarySessionId = secondary.id;
    assert.equal(secondary.userAgentSummary, 'VAJRA-Secondary-Browser/1.0');

    // Cross-user revocation attempt must return 404 SESSION_NOT_FOUND
    const crossRevokeRes = await fetch(
      `${baseUrl}/api/auth/sessions/${secondarySessionId}/revoke`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: otherUserCookie,
          'X-CSRF-Token': otherUserCsrf,
        },
      }
    );
    assert.equal(crossRevokeRes.status, 404);

    // Secondary session still works prior to owner revocation
    const secCheckBefore = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: secondaryOwnerCookie },
    });
    assert.equal(secCheckBefore.status, 200);
    const secBeforeBody = (await secCheckBefore.json()) as { authenticated: boolean };
    assert.equal(secBeforeBody.authenticated, true);
    void secondaryOwnerCsrf;

    // Owner revokes secondary session from primary session
    const revokeRes = await fetch(
      `${baseUrl}/api/auth/sessions/${secondarySessionId}/revoke`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: ownerCookie,
          'X-CSRF-Token': ownerCsrf,
        },
      }
    );
    assert.equal(revokeRes.status, 200);
    const rotated = revokeRes.headers.get('X-Vajra-Csrf-Token');
    if (rotated) ownerCsrf = rotated;
    const revokeBody = (await revokeRes.json()) as {
      status: string;
      sessionId: string;
      revokedCurrent: boolean;
    };
    assert.equal(revokeBody.status, 'session_revoked');
    assert.equal(revokeBody.sessionId, secondarySessionId);
    assert.equal(revokeBody.revokedCurrent, false);

    // Secondary session is immediately invalidated while primary session remains active
    const secCheckAfter = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: secondaryOwnerCookie },
    });
    assert.equal(secCheckAfter.status, 401);

    const listAfterRes = await fetch(`${baseUrl}/api/auth/sessions`, {
      headers: { Cookie: ownerCookie },
    });
    const listAfterJson = (await listAfterRes.json()) as { sessions: Array<{ id: string }> };
    assert.equal(listAfterJson.sessions.length, 1);
  });

  it('synchronizes Device lifecycle/posture on signed heartbeat and reports truthful non-fabricated location status', async () => {
    const { deviceId, keyPair } = await enrollConfirmedDevice('ANDROID', 'Pixel 9 Field Companion');

    // Immediately after confirmation, lifecycleState is TRUSTED and lastHeartbeatAt is null
    const beforeDevRes = await fetch(`${baseUrl}/api/devices/${deviceId}`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(beforeDevRes.status, 200);
    const beforeDevBody = (await beforeDevRes.json()) as {
      device: { lifecycleState: string; connectivityStatus: string; lastHeartbeatAt: string | null };
    };
    assert.equal(beforeDevBody.device.lifecycleState, 'TRUSTED');
    assert.equal(beforeDevBody.device.lastHeartbeatAt, null);

    // Location summary before any heartbeat must NOT fabricate coordinates or 'Within ~25m'
    const beforeActionsRes = await fetch(`${baseUrl}/api/devices/${deviceId}/actions`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(beforeActionsRes.status, 200);
    const beforeActionsBody = (await beforeActionsRes.json()) as {
      locationSummary: {
        accuracyMode: string;
        label: string;
        regionSummary: string;
        updatedAt: string | null;
      };
    };
    assert.equal(beforeActionsBody.locationSummary.updatedAt, null);
    assert.equal(beforeActionsBody.locationSummary.regionSummary.includes('Within ~25m'), false);

    // Send signed Plane-2 heartbeat
    const hbPath = `/api/devices/${deviceId}/heartbeat`;
    const hbPayload = {
      connectivityStatus: 'ONLINE',
      batteryLevel: 86,
      charging: true,
      permissionSummary: 'Notifications granted · Location on request',
      osVersion: 'Android 15 (AP3A)',
      agentVersion: '0.1.0-android',
    };
    const hbTimestamp = new Date().toISOString();
    const hbNonce = crypto.randomBytes(24).toString('hex');
    const hbSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: hbPath,
      deviceId,
      timestampIso: hbTimestamp,
      nonce: hbNonce,
      body: hbPayload,
    });

    const hbRes = await fetch(`${baseUrl}${hbPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': hbTimestamp,
        'X-Vajra-Nonce': hbNonce,
        'X-Vajra-Signature': hbSig,
      },
      body: JSON.stringify(hbPayload),
    });
    assert.equal(hbRes.status, 200);

    // Verify Device record transitioned TRUSTED -> ACTIVE, ONLINE, and updated lastHeartbeatAt + osVersion
    const afterDevRes = await fetch(`${baseUrl}/api/devices/${deviceId}`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(afterDevRes.status, 200);
    const afterDevBody = (await afterDevRes.json()) as {
      device: {
        lifecycleState: string;
        connectivityStatus: string;
        lastHeartbeatAt: string | null;
        osVersion: string | null;
        agentVersion: string | null;
      };
    };
    assert.equal(afterDevBody.device.lifecycleState, 'ACTIVE');
    assert.equal(afterDevBody.device.connectivityStatus, 'ONLINE');
    assert.ok(afterDevBody.device.lastHeartbeatAt);
    assert.equal(afterDevBody.device.osVersion, 'Android 15 (AP3A)');
    assert.equal(afterDevBody.device.agentVersion, '0.1.0-android');

    // Verify security risk assessment no longer penalizes stale/missing heartbeat for this device
    const riskRes = await fetch(`${baseUrl}/api/security/risk`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(riskRes.status, 200);
    const riskBody = (await riskRes.json()) as {
      riskAssessment: { factors: Array<{ code: string }> };
    };
    assert.equal(
      riskBody.riskAssessment.factors.some((f) => f.code === 'DEVICE_HEARTBEAT_STALE'),
      false
    );
  });

  it('returns 409 COMMAND_NOT_CANCELLABLE for acknowledged commands, omits simulator flags, and blocks commands on COMPROMISED devices', async () => {
    const { deviceId, keyPair } = await enrollConfirmedDevice('WINDOWS', 'ThinkPad T14s Workstation');

    // Queue REQUEST_DEVICE_STATUS via /actions and verify simulator flag is NOT injected
    const actionRes = await fetch(`${baseUrl}/api/devices/${deviceId}/actions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({ actionType: 'REQUEST_DEVICE_STATUS' }),
    });
    assert.equal(actionRes.status, 200);
    const rotatedAction = actionRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedAction) ownerCsrf = rotatedAction;
    const actionBody = (await actionRes.json()) as {
      action: { id: string; status: string };
    };
    const commandId = actionBody.action.id;
    assert.equal(actionBody.action.status, 'QUEUED');

    const storedCmd = await repo.findRemoteCommandById(commandId);
    assert.ok(storedCmd);
    assert.equal('simulator' in storedCmd.payloadSummary, false);

    // Agent acknowledges the command via Plane-2 signature
    const ackPath = `/api/devices/${deviceId}/commands/${commandId}/acknowledge`;
    const ackTs = new Date().toISOString();
    const ackNonce = crypto.randomBytes(24).toString('hex');
    const ackSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: ackPath,
      deviceId,
      timestampIso: ackTs,
      nonce: ackNonce,
      body: {},
    });
    const ackRes = await fetch(`${baseUrl}${ackPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ackTs,
        'X-Vajra-Nonce': ackNonce,
        'X-Vajra-Signature': ackSig,
      },
      body: JSON.stringify({}),
    });
    assert.equal(ackRes.status, 200);

    // Owner cancellation after ACKNOWLEDGED must return 409 COMMAND_NOT_CANCELLABLE (never 500)
    const cancelRes = await fetch(
      `${baseUrl}/api/devices/${deviceId}/commands/${commandId}/cancel`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: ownerCookie,
          'X-CSRF-Token': ownerCsrf,
        },
      }
    );
    assert.equal(cancelRes.status, 409);
    const rotatedCancel = cancelRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedCancel) ownerCsrf = rotatedCancel;
    const cancelErr = (await cancelRes.json()) as { error: { code: string } };
    assert.equal(cancelErr.error.code, 'COMMAND_NOT_CANCELLABLE');

    // Mark device COMPROMISED (with step-up) and verify new commands/actions are rejected with 409
    await grantOwnerStepUp('DEVICE_COMPROMISED');
    const compRes = await fetch(`${baseUrl}/api/devices/${deviceId}/compromised`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({ reason: 'Suspected physical tamper during travel' }),
    });
    assert.equal(compRes.status, 200);
    const rotatedComp = compRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedComp) ownerCsrf = rotatedComp;

    const blockedCmdRes = await fetch(`${baseUrl}/api/devices/${deviceId}/commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
      body: JSON.stringify({ actionType: 'REQUEST_DEVICE_STATUS' }),
    });
    assert.equal(blockedCmdRes.status, 409);
    const rotatedBlocked = blockedCmdRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedBlocked) ownerCsrf = rotatedBlocked;
  });

  it('verifies the full SHA-256 tamper-evident audit chain via GET and POST /api/audit/verify including device-attributed entries', async () => {
    const getVerifyRes = await fetch(`${baseUrl}/api/audit/verify`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(getVerifyRes.status, 200);
    const getVerifyBody = (await getVerifyRes.json()) as {
      verification: {
        valid: boolean;
        checkedCount: number;
        userEventCount: number;
        verifiedAt: string;
      };
    };
    assert.equal(getVerifyBody.verification.valid, true);
    assert.ok(getVerifyBody.verification.checkedCount >= 5);
    assert.ok(getVerifyBody.verification.userEventCount >= 5);
    assert.ok(typeof getVerifyBody.verification.verifiedAt === 'string');

    const postVerifyRes = await fetch(`${baseUrl}/api/audit/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: ownerCookie,
        'X-CSRF-Token': ownerCsrf,
      },
    });
    assert.equal(postVerifyRes.status, 200);
    const rotatedPost = postVerifyRes.headers.get('X-Vajra-Csrf-Token');
    if (rotatedPost) ownerCsrf = rotatedPost;
    const postVerifyBody = (await postVerifyRes.json()) as {
      verification: { valid: boolean; checkedCount: number };
    };
    assert.equal(postVerifyBody.verification.valid, true);
    assert.equal(
      postVerifyBody.verification.checkedCount,
      getVerifyBody.verification.checkedCount
    );
  });

  it('enforces production configuration HTTPS origin, public-origin requirement, and PostgreSQL TLS policy', () => {
    const baseProdEnv = {
      NODE_ENV: 'production',
      APP_ENV: 'production',
      DATABASE_URL:
        'postgresql://vajra_app:StrongRuntimeDbPass_9911@pg.vajra.internal:5432/vajra?schema=public&sslmode=require',
      SESSION_SECRET: 'prod_session_secret_0123456789abcdef_extra_entropy',
      TOTP_ENCRYPTION_KEY: 'prod_totp_secret_fedcba9876543210_distinct_entropy',
      PASSCODE_HMAC_SECRET: 'prod_passcode_hmac_secret_0123456789abcdef_distinct_entropy',
      APP_PUBLIC_ORIGIN: 'https://guard.vajra.example',
      REQUIRE_PUBLIC_ORIGIN: 'true',
      DATABASE_SSL_REQUIRED: 'true',
      TRUST_PROXY: 'true',
    };

    const validRes = validateRuntimeConfig(baseProdEnv);
    assert.equal(validRes.valid, true);
    assert.equal(validRes.errors.length, 0);
    assert.equal(validRes.warnings.length, 0);

    const httpOriginRes = validateRuntimeConfig({
      ...baseProdEnv,
      APP_PUBLIC_ORIGIN: 'http://guard.vajra.example',
    });
    assert.equal(httpOriginRes.valid, false);
    assert.ok(httpOriginRes.errors.some((e) => e.includes('https://')));

    const missingOriginRes = validateRuntimeConfig({
      ...baseProdEnv,
      APP_PUBLIC_ORIGIN: '',
    });
    assert.equal(missingOriginRes.valid, false);
    assert.ok(missingOriginRes.errors.some((e) => e.includes('REQUIRE_PUBLIC_ORIGIN')));

    const missingTlsRes = validateRuntimeConfig({
      ...baseProdEnv,
      DATABASE_URL:
        'postgresql://vajra_app:StrongRuntimeDbPass_9911@pg.vajra.internal:5432/vajra?schema=public',
    });
    assert.equal(missingTlsRes.valid, false);
    assert.ok(missingTlsRes.errors.some((e) => e.includes('DATABASE_SSL_REQUIRED')));
  });

  it('includes complete, secret-free operational, Azure Bicep, and native service readiness artifacts', () => {
    const rootDir = process.cwd();
    const expectedFiles = [
      '.env.example',
      '.env.test.example',
      '.env.production.example',
      'infrastructure/azure/main.bicep',
      'infrastructure/azure/main.bicepparam.example',
      'infrastructure/docker/docker-compose.postgres.yml',
      'infrastructure/scripts/startup-app-service.sh',
      'infrastructure/scripts/backup-postgres.sh',
      'infrastructure/scripts/restore-postgres.sh',
      'infrastructure/scripts/azure-preflight.sh',
      'apps/windows-agent/appsettings.Production.json',
      'apps/windows-agent/scripts/publish-release.ps1',
      'apps/windows-agent/scripts/install-service.ps1',
      'apps/windows-agent/scripts/upgrade-service.ps1',
      'apps/windows-agent/scripts/uninstall-service.ps1',
      'scripts/verify-android-agent.mjs',
    ];

    for (const rel of expectedFiles) {
      const fullPath = path.join(rootDir, rel);
      assert.equal(fs.existsSync(fullPath), true, `Expected file to exist: ${rel}`);
      const content = fs.readFileSync(fullPath, 'utf8');
      assert.equal(
        content.includes('-----BEGIN PRIVATE KEY-----'),
        false,
        `Private key material must never appear in ${rel}`
      );
    }

    const prodTemplate = fs.readFileSync(path.join(rootDir, '.env.production.example'), 'utf8');
    assert.ok(prodTemplate.includes('REPLACE_WITH_'));
    assert.ok(prodTemplate.includes('sslmode=require'));
    assert.ok(prodTemplate.includes('VAJRA_ENABLE_DEMO_ENDPOINTS="false"'));
  });
});
