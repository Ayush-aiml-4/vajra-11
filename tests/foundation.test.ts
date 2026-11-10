/**
 * VAJRA Foundation Automated Test Suite (Prompt 0001)
 * Verifies:
 * 1. Backend /api/health endpoint response & security boundaries (zero secret leakage)
 * 2. Shared types (@vajra/shared-types) and mock foundation data integrity
 * 3. Security charter (@vajra/security) prohibited capabilities & log redaction
 * 4. Runtime configuration validation (@vajra/config)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createVajraApiApp } from '../src/server/app.ts';
import {
  DeviceStatus,
  DeviceType,
  RiskLevel,
  CommandStatus,
} from '../packages/shared-types/src/index.ts';
import {
  isCapabilityPermitted,
  sanitizeLogMetadata,
  PROHIBITED_CAPABILITIES,
} from '../packages/security/src/index.ts';
import { validateRuntimeConfig } from '../packages/config/src/index.ts';
import { MOCK_DEVICES } from '../src/data/mockFoundationData.ts';

describe('VAJRA Prompt 0001 Foundation Suite', () => {
  it('GET /api/health returns {"status":"ok","service":"vajra-api"} and exposes no secrets', async () => {
    const app = createVajraApiApp();
    const server = http.createServer(app);

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert(address && typeof address === 'object', 'Server must bind to an ephemeral port');

    try {
      const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');

      const body = (await response.json()) as Record<string, unknown>;
      assert.deepEqual(body, {
        status: 'ok',
        service: 'vajra-api',
      });

      // Ensure no environment variables, secrets, or extra keys are leaked
      assert.deepEqual(Object.keys(body).sort(), ['service', 'status']);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    }
  });

  it('Shared types and mock dashboard data match Prompt 0001 specifications', () => {
    assert.equal(DeviceStatus.ONLINE, 'ONLINE');
    assert.equal(DeviceStatus.OFFLINE, 'OFFLINE');
    assert.equal(DeviceStatus.UNKNOWN, 'UNKNOWN');

    assert.equal(RiskLevel.LOW, 'LOW');
    assert.equal(RiskLevel.MEDIUM, 'MEDIUM');
    assert.equal(RiskLevel.HIGH, 'HIGH');
    assert.equal(RiskLevel.CRITICAL, 'CRITICAL');

    assert.equal(CommandStatus.AUTHORIZED, 'AUTHORIZED');

    assert.equal(MOCK_DEVICES.length, 2);
    assert.equal(MOCK_DEVICES[0].name, 'ASUS TUF F16');
    assert.equal(MOCK_DEVICES[0].type, DeviceType.WINDOWS);
    assert.equal(MOCK_DEVICES[0].status, DeviceStatus.ONLINE);
    assert.equal(MOCK_DEVICES[0].isMockData, true);

    assert.equal(MOCK_DEVICES[1].name, 'Android Phone');
    assert.equal(MOCK_DEVICES[1].type, DeviceType.ANDROID);
    assert.equal(MOCK_DEVICES[1].status, DeviceStatus.ONLINE);
    assert.equal(MOCK_DEVICES[1].isMockData, true);
  });

  it('Security charter rejects prohibited spyware/offensive capabilities and redacts sensitive logs', () => {
    for (const prohibited of PROHIBITED_CAPABILITIES) {
      assert.equal(
        isCapabilityPermitted(prohibited),
        false,
        `Prohibited capability ${prohibited} must be rejected`
      );
    }

    assert.equal(isCapabilityPermitted('ring_device'), true);
    assert.equal(isCapabilityPermitted('heartbeat_check'), true);

    const sanitized = sanitizeLogMetadata({
      deviceId: 'dev-123',
      userPassword: 'super-secret-password',
      authToken: 'bearer-xyz',
      eventType: 'HEARTBEAT_CHECK',
    });

    assert.equal(sanitized.deviceId, 'dev-123');
    assert.equal(sanitized.eventType, 'HEARTBEAT_CHECK');
    assert.equal(sanitized.userPassword, '[REDACTED]');
    assert.equal(sanitized.authToken, '[REDACTED]');
  });

  it('Configuration validator enforces valid ports, environments, and session TTLs', () => {
    const validResult = validateRuntimeConfig({
      NODE_ENV: 'development',
      PORT: '3000',
      SESSION_TTL_SECONDS: '900',
      REQUIRE_MFA: 'true',
    });
    assert.equal(validResult.valid, true);
    assert.equal(validResult.errors.length, 0);
    assert.equal(validResult.config.port, 3000);
    assert.equal(validResult.config.serviceName, 'vajra-api');

    const invalidResult = validateRuntimeConfig({
      NODE_ENV: 'invalid_env',
      PORT: '99999',
      SESSION_TTL_SECONDS: '10',
    });
    assert.equal(invalidResult.valid, false);
    assert.equal(invalidResult.errors.length, 3);
  });
});
