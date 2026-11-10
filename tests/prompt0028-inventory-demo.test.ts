/**
 * Prompt 0028 — inventory honesty & demo endpoint isolation (source + lightweight checks).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();

describe('Prompt 0028 — device inventory honesty', () => {
  const appSrc = readFileSync(join(root, 'src/App.tsx'), 'utf8');

  it('does not map MOCK_DEVICES into the default unified inventory', () => {
    // The real inventory useMemo must return [] when enrolledDevices is empty
    assert.match(
      appSrc,
      /Never present sample devices as the real inventory/
    );
    // Sample preview is opt-in
    assert.match(appSrc, /showSampleDevicePreview/);
    assert.match(appSrc, /Show sample preview/);
  });

  it('surfaces device inventory fetch errors with retry', () => {
    assert.match(appSrc, /devicesError/);
    assert.match(appSrc, /Unable to load your devices/);
    assert.match(appSrc, /Retry/);
  });

  it('empty-state copy does not claim sample devices are shown as real inventory', () => {
    assert.doesNotMatch(
      appSrc,
      /Sample preview devices are shown below/
    );
    assert.match(appSrc, /No devices are enrolled yet/);
  });
});

describe('Prompt 0028 — demo endpoint production gate', () => {
  const routes = readFileSync(
    join(root, 'src/server/notifications/routes.ts'),
    'utf8'
  );

  it('rejects demo events when NODE_ENV or APP_ENV is production', () => {
    assert.match(routes, /DEMO_DISABLED/);
    assert.match(routes, /VAJRA_ENABLE_DEMO_ENDPOINTS/);
    assert.match(routes, /\/demo\/events/);
  });
});
