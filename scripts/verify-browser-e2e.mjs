#!/usr/bin/env node
/**
 * VAJRA — Browser E2E Verification Readiness Runner (Prompt 0036)
 *
 * Checks for required browser E2E prerequisites:
 * 1. Installed browser binary (Chromium / Chrome / Playwright browser cache).
 * 2. `@playwright/test` runner and browser E2E test spec directory (`tests/e2e/`).
 *
 * Never converts a missing browser prerequisite into a pass.
 * Exits with code 2 (BLOCKED) and identifies the missing prerequisites.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const BLOCKED_EXIT_CODE = 2;

function hasCommand(cmd) {
  const res = spawnSync('which', [cmd], { encoding: 'utf8' });
  return res.status === 0 && Boolean(res.stdout.trim());
}

function findPlaywrightCacheBrowsers() {
  const candidates = [
    process.env.PLAYWRIGHT_BROWSERS_PATH,
    path.join(os.homedir(), '.cache', 'ms-playwright'),
    '/ms-playwright',
  ].filter(Boolean);

  for (const dir of candidates) {
    if (fs.existsSync(dir)) {
      try {
        const entries = fs.readdirSync(dir);
        if (entries.some((e) => e.startsWith('chromium') || e.startsWith('firefox') || e.startsWith('webkit'))) {
          return dir;
        }
      } catch {
        // ignore read error
      }
    }
  }
  return null;
}

const systemBrowser = ['chromium', 'chromium-browser', 'google-chrome', ' google-chrome-stable'].find((b) =>
  hasCommand(b.trim())
);
const cachedBrowsersPath = findPlaywrightCacheBrowsers();

const missing = [];
if (!systemBrowser && !cachedBrowsersPath) {
  missing.push(
    'No browser binaries found on PATH (chromium/google-chrome) and ~/.cache/ms-playwright is absent'
  );
}

const localE2eSuite = fs.existsSync(
  path.resolve(process.cwd(), 'tests', 'e2e', 'browser-e2e.test.ts')
);
if (!localE2eSuite) {
  missing.push('No tests/e2e/browser-e2e.test.ts browser E2E suite found');
}

if (missing.length > 0) {
  console.error(`BLOCKED [test:e2e:browser]: Missing prerequisite(s): ${missing.join('; ')}.`);
  console.error(
    'See docs/quality/verification-readiness-0036.md for browser E2E setup instructions and manual smoke-test steps.'
  );
  process.exit(BLOCKED_EXIT_CODE);
}

const distIndex = path.resolve(process.cwd(), 'dist', 'index.html');
if (!fs.existsSync(distIndex)) {
  console.log('[test:e2e:browser] dist/index.html not found; running npm run build...');
  const buildRes = spawnSync('npm', ['run', 'build'], { stdio: 'inherit' });
  if (buildRes.status !== 0) {
    process.exit(buildRes.status ?? 1);
  }
}

console.log(
  `[test:e2e:browser] Browser prerequisite verified (${systemBrowser || cachedBrowsersPath}). Running headless Chromium E2E suite...`
);

const res = spawnSync('npx', ['tsx', '--test', 'tests/e2e/browser-e2e.test.ts'], {
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_ENV: 'test',
    APP_ENV: 'test',
  },
});
process.exit(res.status ?? 1);
