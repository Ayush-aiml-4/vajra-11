/**
 * VAJRA — Real Headless Chromium Browser E2E Suite (Prompt 0037)
 *
 * Executes real browser user flows in headless Chromium via `playwright-core`
 * against a live Express + built React SPA server instance:
 * 1. Owner registration, authenticated console load, sign-out, and sign-in.
 * 2. Empty device inventory honesty (0 enrolled devices) & opt-in sample preview toggle.
 * 3. Keyboard-accessible dialogs (Modal & NotificationSlideOverPanel: role="dialog",
 *    aria-modal="true", Tab/Shift+Tab focus containment, Escape dismissal) & mobile viewport (375x812).
 * 4. TOTP Multi-Factor Authentication setup, 8 single-use recovery codes, and MFA sign-in.
 * 5. ThreatCheck URL inspection, secret redaction (`access_token=[REDACTED]`), explainable indicators,
 *    and lexical limitation disclosure.
 * 6. Enrolled Windows device inventory rendering, DetailDrawer inspection, status check queueing,
 *    and MFA step-up gating for Lost Mode.
 * 7. Persisted Security Analytics & JSON/CSV report export verification.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core';
import { PrismaClient } from '@prisma/client';
import { createVajraApiApp } from '../../src/server/app.ts';
import {
  InMemoryIdentityRepository,
  PrismaIdentityRepository,
  type IdentityRepository,
} from '../../src/server/db/repository.ts';
import {
  generateTotpCodeAtTime,
  generateDeviceKeyPair,
  signEnrollmentProof,
  signDeviceRequest,
} from '../../packages/security/src/node.ts';

function isPlaceholderDatabaseUrl(url: string): boolean {
  const u = url.trim().toLowerCase();
  if (!u) return true;
  return (
    u.includes('username:password@') ||
    u.includes('user:password@') ||
    u.includes('localhost:5432/vajra_db') ||
    u.includes('example.com') ||
    u.includes('changeme')
  );
}

const DATABASE_URL = process.env.DATABASE_URL?.trim() ?? '';
const USE_PG =
  (DATABASE_URL.startsWith('postgresql://') || DATABASE_URL.startsWith('postgres://')) &&
  !isPlaceholderDatabaseUrl(DATABASE_URL);
const TOTP_KEY = 'vajra-browser-e2e-totp-key-32bytes!';

describe('Browser E2E — Headless Chromium against live VAJRA full-stack server', () => {
  let prisma: PrismaClient | null = null;
  let repository: IdentityRepository;
  let server: http.Server;
  let baseUrl = '';
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  const runSuffix = crypto.randomBytes(4).toString('hex');
  const ownerEmail = `e2e.owner.${runSuffix}@vajra.test`;
  const ownerPassword = 'Vajra-E2E-StrongPass!2026';
  const ownerName = 'Aarav E2E Owner';
  let totpSecretBase32 = '';

  before(async () => {
    const distPath = path.resolve(process.cwd(), 'dist');
    const indexHtmlPath = path.join(distPath, 'index.html');
    assert.ok(
      fs.existsSync(indexHtmlPath),
      'dist/index.html is missing — run `npm run build` before browser E2E tests'
    );

    if (USE_PG) {
      try {
        prisma = new PrismaClient({ datasources: { db: { url: DATABASE_URL } } });
        await prisma.$connect();
        repository = new PrismaIdentityRepository(prisma);
        console.log('[browser-e2e] Repository backend: POSTGRESQL_PRISMA');
      } catch {
        repository = new InMemoryIdentityRepository();
        prisma = null;
        console.log('[browser-e2e] Repository backend: IN_MEMORY (PostgreSQL unreachable fallback)');
      }
    } else {
      repository = new InMemoryIdentityRepository();
      console.log('[browser-e2e] Repository backend: IN_MEMORY');
    }

    const app = createVajraApiApp({
      repository,
      totpEncryptionKey: TOTP_KEY,
      frameAncestors: 'https://studio-parent.other-site.example:*',
    });

    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        next();
        return;
      }
      res.sendFile(indexHtmlPath);
    });

    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    baseUrl = `http://127.0.0.1:${addr.port}`;

    const launchOpts: Record<string, unknown> = {
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    };
    if (fs.existsSync('/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell')) {
      launchOpts.executablePath = '/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell';
    } else if (fs.existsSync('/ms-playwright/chrome-headless-shell-linux64/chrome-headless-shell')) {
      launchOpts.executablePath = '/ms-playwright/chrome-headless-shell-linux64/chrome-headless-shell';
    }

    browser = await chromium.launch(launchOpts);
    context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    page = await context.newPage();

    // Prevent external decorative video asset from slowing down headless tests
    await page.route('**res.cloudinary.com**', (route) => route.abort());
  });

  after(async () => {
    try {
      await context?.close();
    } catch {
      /* ignore */
    }
    try {
      await browser?.close();
    } catch {
      /* ignore */
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (prisma) {
      try {
        await prisma.$disconnect();
      } catch {
        /* ignore */
      }
    }
  });

  it('1. registers a new owner account, loads the Overview console, signs out, and signs back in', async () => {
    const initialRes = await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
    assert.ok(initialRes, 'Expected initial HTML navigation response');
    const cspHeader = initialRes.headers()['content-security-policy'] ?? '';
    assert.doesNotMatch(cspHeader, /frame-ancestors\s+\*/i, 'CSP must never allow wildcard frame-ancestors *');
    assert.doesNotMatch(cspHeader, /unsafe-eval/i, 'CSP must not include script-src unsafe-eval');
    assert.match(cspHeader, /frame-ancestors\s+'self'/i, 'CSP must include explicit frame-ancestors policy');

    await page.getByRole('button', { name: 'Create Account' }).click();
    await page.locator('#vajra-reg-name').fill(ownerName);
    await page.locator('#vajra-reg-email').fill(ownerEmail);
    await page.locator('#vajra-reg-password').fill(ownerPassword);
    await page.locator('#vajra-reg-confirm').fill(ownerPassword);
    await page.getByRole('button', { name: 'Create VAJRA Account' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
    const bodyText = await page.locator('body').innerText();
    assert.match(bodyText, /Aarav/);

    // Navigate to Settings and Sign Out
    await page.getByRole('button', { name: 'Settings' }).first().click();
    await page.getByRole('button', { name: 'Sign Out', exact: true }).click();

    await page.locator('#vajra-login-email').waitFor({ state: 'visible', timeout: 10000 });
    await page.locator('#vajra-login-email').fill(ownerEmail);
    await page.locator('#vajra-login-password').fill(ownerPassword);
    await page.getByRole('button', { name: 'Sign In to VAJRA' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
  });

  it('2. displays honest empty device inventory by default and toggles opt-in sample preview', async () => {
    await page.getByRole('button', { name: 'Devices' }).first().click();
    await page.getByText('Protect your first device').waitFor({ state: 'visible', timeout: 10000 });

    const defaultText = await page.locator('body').innerText();
    assert.match(defaultText, /No devices are enrolled yet/i);
    assert.doesNotMatch(defaultText, /ASUS TUF F16/);

    await page.getByRole('button', { name: 'Show sample preview' }).click();
    await page.getByText('ASUS TUF F16 (Sample)').waitFor({ state: 'visible', timeout: 5000 });
    const previewText = await page.locator('body').innerText();
    assert.match(previewText, /Sample only/);
    assert.match(previewText, /Not a real device/);

    await page.getByRole('button', { name: 'Hide sample preview' }).click();
    const afterHideCount = await page.getByText('ASUS TUF F16 (Sample)').count();
    assert.equal(afterHideCount, 0);
  });

  it('3. enforces keyboard-accessible dialogs (Modal & NotificationSlideOverPanel) and responsive mobile layout', async () => {
    // Open Connect Device modal
    await page.getByRole('button', { name: 'Connect Device' }).first().click();

    const dialog = page.locator('[role="dialog"][aria-modal="true"]').first();
    await dialog.waitFor({ state: 'visible', timeout: 5000 });

    // Verify Tab / Shift+Tab keeps focus inside the modal dialog
    await page.keyboard.press('Tab');
    const focusInsideAfterTab = await page.evaluate(() => {
      const dlg = document.querySelector('[role="dialog"][aria-modal="true"]');
      return Boolean(dlg && dlg.contains(document.activeElement));
    });
    assert.equal(focusInsideAfterTab, true, 'expected Tab focus to remain inside open dialog');

    await page.keyboard.press('Shift+Tab');
    const focusInsideAfterShiftTab = await page.evaluate(() => {
      const dlg = document.querySelector('[role="dialog"][aria-modal="true"]');
      return Boolean(dlg && dlg.contains(document.activeElement));
    });
    assert.equal(focusInsideAfterShiftTab, true, 'expected Shift+Tab focus to remain inside open dialog');

    // Dismiss modal with Escape key
    await page.keyboard.press('Escape');
    await dialog.waitFor({ state: 'hidden', timeout: 5000 });

    // Open NotificationSlideOverPanel via header bell button and dismiss with Escape
    await page.locator('button[aria-label^="Notifications"]').first().click();
    const notifDialog = page.locator('[role="dialog"][aria-modal="true"][aria-label="Notification Center"]');
    await notifDialog.waitFor({ state: 'visible', timeout: 5000 });
    await page.keyboard.press('Escape');
    await notifDialog.waitFor({ state: 'hidden', timeout: 5000 });

    // Verify mobile viewport (375x812) has no horizontal overflow
    await page.setViewportSize({ width: 375, height: 812 });
    const overflowCheck = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }));
    assert.ok(
      overflowCheck.scrollWidth <= overflowCheck.clientWidth + 1,
      `expected no horizontal overflow on mobile viewport (scrollWidth=${overflowCheck.scrollWidth}, clientWidth=${overflowCheck.clientWidth})`
    );
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  it('4. sets up TOTP MFA, displays 8 single-use recovery codes, and verifies MFA login', async () => {
    await page.getByRole('button', { name: 'Settings' }).first().click();
    await page.getByRole('button', { name: 'Enable Two-Step' }).click();

    await page.getByRole('button', { name: 'View manual setup key' }).click();
    const secretEl = page.locator('div.font-mono.text-\\[\\#C8A66A\\]').first();
    await secretEl.waitFor({ state: 'visible', timeout: 5000 });
    totpSecretBase32 = (await secretEl.innerText()).trim();
    assert.match(totpSecretBase32, /^[A-Z2-7]+=*$/);

    const code = generateTotpCodeAtTime(totpSecretBase32);
    await page.locator('#mfa-verify-code').fill(code);
    await page.getByRole('button', { name: 'Activate' }).click();

    await page.getByText('Protected with authenticator app').waitFor({ state: 'visible', timeout: 10000 });
    await page.getByText('Recovery Codes').first().waitFor({ state: 'visible', timeout: 5000 });

    const pageText = await page.locator('body').innerText();
    const recoveryMatches = pageText.match(/\b[A-Z0-9]{4}-[A-Z0-9]{4}\b/g) ?? [];
    assert.ok(
      recoveryMatches.length >= 8,
      `expected 8 single-use recovery codes, found ${recoveryMatches.length}`
    );

    // Sign out and verify MFA challenge during login
    await page.getByRole('button', { name: 'Sign Out', exact: true }).click();
    await page.locator('#vajra-login-email').waitFor({ state: 'visible', timeout: 10000 });
    await page.locator('#vajra-login-email').fill(ownerEmail);
    await page.locator('#vajra-login-password').fill(ownerPassword);
    await page.getByRole('button', { name: 'Sign In to VAJRA' }).click();

    await page.locator('#vajra-login-totp').waitFor({ state: 'visible', timeout: 10000 });
    const loginTotp = generateTotpCodeAtTime(totpSecretBase32);
    await page.locator('#vajra-login-totp').fill(loginTotp);
    await page.getByRole('button', { name: 'Verify & Sign In' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
  });

  it('5. inspects a restricted URL in ThreatCheck, redacts secrets, and renders explainable indicators & limitations', async () => {
    await page.getByRole('button', { name: 'ThreatCheck' }).first().click();

    const urlInput = page.locator('input[aria-label="Website address to inspect"]');
    await urlInput.waitFor({ state: 'visible', timeout: 5000 });
    await urlInput.fill('http://127.0.0.1:8080/admin?access_token=SECRET123#frag');
    await page.getByRole('button', { name: 'Check Link' }).click();

    await page
      .getByText('Restricted Destination Boundary Flagged')
      .waitFor({ state: 'visible', timeout: 10000 });

    const tcText = await page.locator('body').innerText();
    assert.match(tcText, /HIGH RISK/);
    assert.match(tcText, /Explainable Threat Indicators/i);
    assert.match(tcText, /Limitations note:/i);
    assert.match(tcText, /access_token=\[REDACTED\]/);
    assert.doesNotMatch(tcText, /SECRET123/);
  });

  it('6. enrolls a Windows device, renders it in inventory, queues a status check, and gates Lost Mode behind MFA step-up', async () => {
    // Enroll a Windows device using the browser's authenticated session + protocol enrollment submit
    const enrollInfo = await page.evaluate(async () => {
      const meRes = await fetch('/api/auth/me', { credentials: 'include' });
      const meData = await meRes.json();
      const csrf = meData.csrfToken;
      const initRes = await fetch('/api/devices/enrollment/initiate', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: JSON.stringify({
          name: 'Win11-Workstation-E2E',
          deviceType: 'WINDOWS',
          osVersion: 'Windows 11 Pro 23H2',
        }),
      });
      const initData = await initRes.json();
      return { status: initRes.status, csrf, enrollment: initData.enrollment };
    });

    assert.equal(enrollInfo.status, 201);
    const { deviceId, enrollmentToken, challengeNonce } = enrollInfo.enrollment;
    const keyPair = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      deviceId,
      enrollmentToken,
      challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const submitStatus = await page.evaluate(
      async (payload) => {
        const subRes = await fetch('/api/devices/enrollment/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload.submitBody),
        });
        const confRes = await fetch(`/api/devices/${payload.deviceId}/enrollment/confirm`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': payload.csrf,
          },
        });
        return { subStatus: subRes.status, confStatus: confRes.status };
      },
      {
        deviceId,
        csrf: enrollInfo.csrf,
        submitBody: {
          enrollmentToken,
          publicKeyPem: keyPair.publicKeyPem,
          keyAlgorithm: 'ECDSA_P256',
          signatureBase64,
          timestampIso,
          clientNonce,
          hardwareBacked: false,
        },
      }
    );
    assert.ok(submitStatus.subStatus === 200 || submitStatus.subStatus === 201);
    assert.ok(submitStatus.confStatus === 200 || submitStatus.confStatus === 201);

    // Reload Devices view in browser and inspect the enrolled device card
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'Devices' }).first().click();
    await page.getByRole('heading', { name: 'Win11-Workstation-E2E' }).first().waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('heading', { name: 'Win11-Workstation-E2E' }).first().click();
    const drawer = page.locator('aside[role="dialog"][aria-modal="true"]');
    await drawer.waitFor({ state: 'visible', timeout: 5000 });

    // Queue REQUEST_DEVICE_STATUS and verify queued honesty (awaiting device agent delivery)
    await drawer.getByRole('button', { name: 'Request Status Check' }).click();
    await page
      .getByText(/Waiting for device agent delivery|queued/i)
      .first()
      .waitFor({ state: 'visible', timeout: 10000 });
    await drawer.getByText(/State:\s*QUEUED/i).first().waitFor({ state: 'visible', timeout: 5000 });

    // Exercise signed command poll -> acknowledge -> authentic result receipt and verify UI status update
    const pollPath = `/api/devices/${deviceId}/commands/pending`;
    const pollTs = new Date().toISOString();
    const pollNonce = crypto.randomUUID();
    const pollSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'GET',
      path: pollPath,
      deviceId,
      timestampIso: pollTs,
      nonce: pollNonce,
      body: undefined,
    });
    const pollRes = await fetch(`${baseUrl}${pollPath}`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': pollTs,
        'X-Vajra-Nonce': pollNonce,
        'X-Vajra-Signature': pollSig,
      },
    });
    assert.equal(pollRes.status, 200);
    const pollData = (await pollRes.json()) as { commands: Array<{ id: string }> };
    assert.ok(Array.isArray(pollData.commands) && pollData.commands.length >= 1);
    const queuedCommandId = pollData.commands[0].id;

    const ackPath = `/api/devices/${deviceId}/commands/${queuedCommandId}/acknowledge`;
    const ackBody = { message: 'Acknowledged by signed E2E harness' };
    const ackTs = new Date().toISOString();
    const ackNonce = crypto.randomUUID();
    const ackSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: ackPath,
      deviceId,
      timestampIso: ackTs,
      nonce: ackNonce,
      body: ackBody,
    });
    const ackRes = await fetch(`${baseUrl}${ackPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ackTs,
        'X-Vajra-Nonce': ackNonce,
        'X-Vajra-Signature': ackSig,
      },
      body: JSON.stringify(ackBody),
    });
    assert.ok(ackRes.status === 200 || ackRes.status === 201);

    const resultPath = `/api/devices/${deviceId}/commands/${queuedCommandId}/result`;
    const receiptMessage = 'Signed E2E status receipt confirmed';
    const resultBody = {
      status: 'COMPLETED',
      safeMessage: receiptMessage,
      executionLatencyMs: 18,
      metadata: { posture: 'HEALTHY' },
    };
    const resultTs = new Date().toISOString();
    const resultNonce = crypto.randomUUID();
    const resultSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: resultPath,
      deviceId,
      timestampIso: resultTs,
      nonce: resultNonce,
      body: resultBody,
    });
    const resultRes = await fetch(`${baseUrl}${resultPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': resultTs,
        'X-Vajra-Nonce': resultNonce,
        'X-Vajra-Signature': resultSig,
      },
      body: JSON.stringify(resultBody),
    });
    assert.ok(resultRes.status === 200 || resultRes.status === 201);

    // Reopen drawer so UI fetches updated command receipt and verify State: COMPLETED
    await page.keyboard.press('Escape');
    await drawer.waitFor({ state: 'hidden', timeout: 5000 });
    await page.getByRole('heading', { name: 'Win11-Workstation-E2E' }).first().click();
    await drawer.waitFor({ state: 'visible', timeout: 5000 });
    await drawer.getByText(receiptMessage).first().waitFor({ state: 'visible', timeout: 10000 });
    await drawer.getByText(/State:\s*COMPLETED/i).first().waitFor({ state: 'visible', timeout: 5000 });

    // Gate Lost Mode behind action-scoped MFA step-up in the browser UI
    await drawer.getByRole('button', { name: /Lost Mode/i }).click();
    await page.getByRole('button', { name: 'Enable Lost Mode' }).click();

    const stepUpInput = page.locator('#step-up-totp-input');
    await stepUpInput.waitFor({ state: 'visible', timeout: 10000 });
    await page.getByText(/Scope:\s*ENABLE_LOST_MODE/i).waitFor({ state: 'visible', timeout: 5000 });

    const stepUpTotp = generateTotpCodeAtTime(totpSecretBase32);
    await stepUpInput.fill(stepUpTotp);
    await page.getByRole('button', { name: 'Verify', exact: true }).click();

    await drawer.getByRole('button', { name: /Turn Off Lost Mode/i }).waitFor({
      state: 'visible',
      timeout: 10000,
    });

    // Close drawer with Escape
    await page.keyboard.press('Escape');
    await drawer.waitFor({ state: 'hidden', timeout: 5000 });
  });

  it('7. renders persisted Security Analytics and exports JSON and CSV reports with no-store headers', async () => {
    await page.getByRole('button', { name: 'Overview' }).first().click();
    await page
      .getByText('Security Analytics & Report Export')
      .first()
      .waitFor({ state: 'visible', timeout: 10000 });

    const exportChecks = await page.evaluate(async () => {
      const jsonRes = await fetch('/api/reports/export?format=json', {
        credentials: 'include',
      });
      const csvRes = await fetch('/api/reports/export?format=csv', {
        credentials: 'include',
      });
      return {
        jsonStatus: jsonRes.status,
        jsonCache: jsonRes.headers.get('cache-control'),
        csvStatus: csvRes.status,
        csvCache: csvRes.headers.get('cache-control'),
        csvText: await csvRes.text(),
      };
    });

    assert.equal(exportChecks.jsonStatus, 200);
    assert.match(String(exportChecks.jsonCache), /no-store/i);
    assert.equal(exportChecks.csvStatus, 200);
    assert.match(String(exportChecks.csvCache), /no-store/i);
    assert.match(exportChecks.csvText, /Win11-Workstation-E2E/);
  });

  it('8. enrolls an Android device via the 3-step browser WebCrypto wizard and verifies cross-server persistence when PostgreSQL-backed', async () => {
    await page.getByRole('button', { name: 'Devices' }).first().click();
    await page.getByRole('button', { name: 'Connect Device' }).first().click();

    const connectDialog = page.locator('[role="dialog"][aria-modal="true"]').first();
    await connectDialog.waitFor({ state: 'visible', timeout: 5000 });

    // Step 01: Choose Android & name device
    await connectDialog.getByRole('button', { name: /Android/i }).click();
    await connectDialog.locator('#connect-device-name').fill('Pixel-9-Wizard-E2E');
    await connectDialog.getByRole('button', { name: 'Continue to Pairing' }).click();

    // Step 02: Pair using real browser WebCrypto ECDSA P-256 key generation & DER proof
    await connectDialog.getByRole('button', { name: 'Complete Pairing' }).waitFor({
      state: 'visible',
      timeout: 10000,
    });
    await connectDialog.getByRole('button', { name: 'Complete Pairing' }).click();

    // Step 03: Owner approval
    await connectDialog.getByRole('button', { name: 'Approve & Protect Device' }).waitFor({
      state: 'visible',
      timeout: 10000,
    });
    await connectDialog.getByRole('button', { name: 'Approve & Protect Device' }).click();
    await connectDialog.waitFor({ state: 'hidden', timeout: 10000 });

    await page.getByText('Pixel-9-Wizard-E2E').first().waitFor({ state: 'visible', timeout: 10000 });

    if (prisma !== null) {
      // Spin up an independent Express + PrismaClient server instance to prove real database-boundary survival
      const distPath = path.resolve(process.cwd(), 'dist');
      const indexHtmlPath = path.join(distPath, 'index.html');
      const secondPrisma = new PrismaClient({ datasources: { db: { url: DATABASE_URL } } });
      await secondPrisma.$connect();
      const secondApp = createVajraApiApp({
        repository: new PrismaIdentityRepository(secondPrisma),
        totpEncryptionKey: TOTP_KEY,
      });
      secondApp.use(express.static(distPath));
      secondApp.get('*', (req, res, next) => {
        if (req.path.startsWith('/api')) {
          next();
          return;
        }
        res.sendFile(indexHtmlPath);
      });
      const secondServer = http.createServer(secondApp);
      await new Promise<void>((resolve) => secondServer.listen(0, '127.0.0.1', () => resolve()));
      const secondAddr = secondServer.address();
      assert.ok(secondAddr && typeof secondAddr === 'object');
      const secondUrl = `http://127.0.0.1:${secondAddr.port}`;

      const secondContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
      const secondPage = await secondContext.newPage();
      await secondPage.route('**res.cloudinary.com**', (route) => route.abort());

      try {
        await secondPage.goto(secondUrl, { waitUntil: 'domcontentloaded' });
        await secondPage.locator('#vajra-login-email').fill(ownerEmail);
        await secondPage.locator('#vajra-login-password').fill(ownerPassword);
        await secondPage.getByRole('button', { name: 'Sign In to VAJRA' }).click();

        await secondPage.locator('#vajra-login-totp').waitFor({ state: 'visible', timeout: 10000 });
        await secondPage.locator('#vajra-login-totp').fill(generateTotpCodeAtTime(totpSecretBase32));
        await secondPage.getByRole('button', { name: 'Verify & Sign In' }).click();

        await secondPage.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
        await secondPage.getByRole('button', { name: 'Devices' }).first().click();

        await secondPage.getByText('Win11-Workstation-E2E').first().waitFor({ state: 'visible', timeout: 10000 });
        await secondPage.getByText('Pixel-9-Wizard-E2E').first().waitFor({ state: 'visible', timeout: 10000 });
      } finally {
        await secondContext.close().catch(() => {});
        await new Promise<void>((resolve) => secondServer.close(() => resolve()));
        await secondPrisma.$disconnect().catch(() => {});
      }
    } else {
      assert.ok(
        repository instanceof InMemoryIdentityRepository,
        'expected InMemoryIdentityRepository when DATABASE_URL is unset or placeholder'
      );
    }
  });

  it('9. signs in reliably inside a cross-site HTTPS iframe behind an HTTP reverse proxy, preserves password & surfaces errors on failure, prevents duplicate submit, restores session on reload, and signs out cleanly', async () => {
    const backendAddr = server.address();
    assert.ok(backendAddr && typeof backendAddr === 'object');
    const backendPort = backendAddr.port;

    const certSuffix = crypto.randomBytes(4).toString('hex');
    const keyPath = path.join(os.tmpdir(), `vajra-e2e-${certSuffix}.key`);
    const certPath = path.join(os.tmpdir(), `vajra-e2e-${certSuffix}.crt`);
    let keyPem = '';
    let certPem = '';
    try {
      execFileSync(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          keyPath,
          '-out',
          certPath,
          '-days',
          '1',
          '-subj',
          '/CN=vajra-e2e-iframe.local',
        ],
        { stdio: 'ignore' }
      );
      keyPem = fs.readFileSync(keyPath, 'utf8');
      certPem = fs.readFileSync(certPath, 'utf8');
    } finally {
      if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
      if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
    }

    // Simulate container sidecar Nginx: terminates HTTPS externally, forwards plain HTTP to Express
    // with Host rewritten to localhost:<backendPort>, X-Forwarded-Proto: http, and X-Forwarded-Host.
    let latestLoginSetCookieRedacted = '';
    const proxyServer = https.createServer({ key: keyPem, cert: certPem }, (req, res) => {
      const incomingHost = req.headers.host || 'vajra-preview.app-site.example';
      const fwdHeaders: http.OutgoingHttpHeaders = {
        ...req.headers,
        host: `localhost:${backendPort}`,
        'x-forwarded-host': incomingHost,
        'x-forwarded-proto': 'http',
      };
      const upstream = http.request(
        {
          host: '127.0.0.1',
          port: backendPort,
          method: req.method,
          path: req.url,
          headers: fwdHeaders,
        },
        (upRes) => {
          if (req.url === '/api/auth/login' && upRes.statusCode === 200) {
            const rawSc = upRes.headers['set-cookie'];
            const joined = Array.isArray(rawSc) ? rawSc.join(' | ') : String(rawSc ?? '');
            latestLoginSetCookieRedacted = joined.replace(
              /(__Host-vajra_session|vajra_session)=[^;]+/g,
              '$1=[REDACTED]'
            );
          }
          res.writeHead(upRes.statusCode ?? 502, upRes.headers);
          upRes.pipe(res);
        }
      );
      upstream.on('error', () => {
        res.writeHead(502);
        res.end('Bad Gateway');
      });
      req.pipe(upstream);
    });
    await new Promise<void>((resolve) => proxyServer.listen(0, '127.0.0.1', () => resolve()));
    const proxyAddr = proxyServer.address();
    assert.ok(proxyAddr && typeof proxyAddr === 'object');
    const proxyPort = proxyAddr.port;

    let parentServer: https.Server | null = null;
    let iframeBrowser: Browser | null = null;

    try {
      const iframeSrc = `https://vajra-preview.app-site.example:${proxyPort}/`;
      parentServer = https.createServer({ key: keyPem, cert: certPem }, (_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(
          `<!doctype html><html><body style="margin:0"><iframe id="preview" src="${iframeSrc}" style="width:1280px;height:800px;border:0"></iframe></body></html>`
        );
      });
      await new Promise<void>((resolve) => parentServer!.listen(0, '127.0.0.1', () => resolve()));
      const parentAddr = parentServer.address();
      assert.ok(parentAddr && typeof parentAddr === 'object');
      const parentPort = parentAddr.port;

      const iframeLaunchOpts: Record<string, unknown> = {
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--test-third-party-cookie-phaseout',
          '--host-resolver-rules=MAP vajra-preview.app-site.example 127.0.0.1, MAP studio-parent.other-site.example 127.0.0.1',
        ],
      };
      if (
        fs.existsSync(
          '/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell'
        )
      ) {
        iframeLaunchOpts.executablePath =
          '/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell';
      } else if (
        fs.existsSync('/ms-playwright/chrome-headless-shell-linux64/chrome-headless-shell')
      ) {
        iframeLaunchOpts.executablePath =
          '/ms-playwright/chrome-headless-shell-linux64/chrome-headless-shell';
      }

      iframeBrowser = await chromium.launch(iframeLaunchOpts);
      const iframeContext = await iframeBrowser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1280, height: 800 },
      });
      const hostPage = await iframeContext.newPage();
      await hostPage.route('**res.cloudinary.com**', (route) => route.abort());

      // Create a dedicated non-MFA disposable account via the reverse proxy so we directly test
      // single-step password sign-in inside the cross-site HTTPS iframe
      const iframeUserEmail = `iframe.login.${runSuffix}@vajra.test`;
      const iframeUserPassword = 'Iframe-Login-Pass!2026';
      const seedRes = await fetch(`http://127.0.0.1:${backendPort}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          email: iframeUserEmail,
          displayName: 'Iframe Auth Tester',
          password: iframeUserPassword,
        }),
      });
      assert.equal(seedRes.status, 201);

      await hostPage.goto(`https://studio-parent.other-site.example:${parentPort}/`, {
        waitUntil: 'domcontentloaded',
      });
      const frame = hostPage.frameLocator('#preview');
      const emailInput = frame.locator('#vajra-login-email');
      const passwordInput = frame.locator('#vajra-login-password');
      const signInBtn = frame.getByRole('button', { name: 'Sign In to VAJRA' });
      const alertBanner = frame.locator('#vajra-auth-error');

      await emailInput.waitFor({ state: 'visible', timeout: 10000 });

      // (a) Invalid credentials -> visible error banner, button restored, password NOT cleared
      await emailInput.fill(iframeUserEmail);
      await passwordInput.fill('Wrong-Password-Attempt!99');
      await signInBtn.click();
      await alertBanner.waitFor({ state: 'visible', timeout: 10000 });
      assert.match(await alertBanner.innerText(), /Invalid credentials/i);
      assert.equal(await passwordInput.inputValue(), 'Wrong-Password-Attempt!99');
      await signInBtn.waitFor({ state: 'visible', timeout: 5000 });

      // (b) Server 503 non-JSON HTML error -> distinct unavailable message, button restored, password preserved
      let interceptMode:
        | 'NONE'
        | 'ERR_503'
        | 'ERR_500'
        | 'NET_FAIL'
        | 'DELAY_DUP'
        | 'COOKIE_CHECK_ONCE'
        | 'WARMUP_ONCE' = 'ERR_503';
      let loginDispatchCount = 0;
      let warmupInterceptedCount = 0;

      await hostPage.route('**/api/auth/login', async (route) => {
        loginDispatchCount += 1;
        if (interceptMode === 'ERR_503') {
          await route.fulfill({
            status: 503,
            contentType: 'text/html',
            body: '<html><body>503 Service Unavailable</body></html>',
          });
          return;
        }
        if (interceptMode === 'ERR_500') {
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: JSON.stringify({ error: { code: 'INTERNAL_ERROR' } }),
          });
          return;
        }
        if (interceptMode === 'NET_FAIL') {
          await route.abort('failed');
          return;
        }
        if (interceptMode === 'DELAY_DUP') {
          await new Promise((r) => setTimeout(r, 250));
          await route.fulfill({
            status: 503,
            contentType: 'application/json',
            body: JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE' } }),
          });
          return;
        }
        if (interceptMode === 'COOKIE_CHECK_ONCE') {
          interceptMode = 'NONE';
          await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: '<!doctype html><html><head><title>Redirecting...</title></head><body><script>document.cookie="__SECURE-aistudio_auth_flow_may_set_cookies=true";</script></body></html>',
          });
          return;
        }
        if (interceptMode === 'WARMUP_ONCE') {
          warmupInterceptedCount += 1;
          interceptMode = 'NONE';
          await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: '<!doctype html><html><head><title>Starting Server...</title></head><body><script>sessionStorage.setItem("warmup_start_time","1");</script><p>Starting Server...</p></body></html>',
          });
          return;
        }
        await route.continue();
      });

      await passwordInput.fill(iframeUserPassword);
      await signInBtn.click();
      await alertBanner.waitFor({ state: 'visible', timeout: 10000 });
      assert.match(await alertBanner.innerText(), /temporarily unavailable/i);
      assert.equal(await passwordInput.inputValue(), iframeUserPassword);

      // (c) Server 500 error -> distinct unexpected server error message
      interceptMode = 'ERR_500';
      await signInBtn.click();
      await alertBanner.waitFor({ state: 'visible', timeout: 10000 });
      assert.match(await alertBanner.innerText(), /unexpected server error/i);
      assert.equal(await passwordInput.inputValue(), iframeUserPassword);

      // (d) Network failure -> clear network connectivity error message
      interceptMode = 'NET_FAIL';
      await signInBtn.click();
      await alertBanner.waitFor({ state: 'visible', timeout: 10000 });
      assert.match(await alertBanner.innerText(), /Unable to reach VAJRA right now/i);
      assert.equal(await passwordInput.inputValue(), iframeUserPassword);

      // (e) Duplicate submit prevention -> rapid concurrent form submissions send only 1 network request
      interceptMode = 'DELAY_DUP';
      loginDispatchCount = 0;
      const previewFrame = hostPage.frames().find((f) => f !== hostPage.mainFrame());
      assert.ok(previewFrame, 'Expected embedded preview frame');
      await previewFrame.evaluate(() => {
        const form = document.querySelector('form');
        form?.requestSubmit();
        form?.requestSubmit();
        form?.requestSubmit();
      });
      await signInBtn.waitFor({ state: 'visible', timeout: 10000 });
      assert.equal(loginDispatchCount, 1, 'Concurrent form submit must dispatch only one request');

      // (e2) Simulated expired gateway auth cookie returning HTTP 200 cookie_check.html -> triggers
      //      automatic iframe reload to refresh gateway session and restores typed email from sessionStorage
      await previewFrame.evaluate(() => {
        (window as unknown as Record<string, boolean>).__preGatewayReloadMarker = true;
      });
      await passwordInput.fill(iframeUserPassword);
      interceptMode = 'COOKIE_CHECK_ONCE';
      await signInBtn.click();
      for (let attempt = 0; attempt < 40; attempt += 1) {
        const currentFrame = hostPage.frames().find((f) => f !== hostPage.mainFrame());
        const stillOldDocument = await currentFrame
          ?.evaluate(() =>
            Boolean((window as unknown as Record<string, boolean>).__preGatewayReloadMarker)
          )
          .catch(() => true);
        if (!stillOldDocument) {
          break;
        }
        await new Promise((r) => setTimeout(r, 150));
      }
      await emailInput.waitFor({ state: 'visible', timeout: 10000 });
      assert.equal(
        await emailInput.inputValue(),
        iframeUserEmail,
        'Typed email should be restored from sessionStorage after automatic gateway reload'
      );
      await passwordInput.fill(iframeUserPassword);

      // (f) Simulated browser cookie blocking (401 on post-login /api/auth/me) -> explicit cookie-blocked alert
      interceptMode = 'NONE';
      let blockNextMe = true;
      await hostPage.route('**/api/auth/me', async (route) => {
        if (blockNextMe) {
          blockNextMe = false;
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({
              error: { code: 'UNAUTHENTICATED', message: 'Authentication is required.' },
            }),
          });
          return;
        }
        await route.continue();
      });

      await signInBtn.click();
      await alertBanner.waitFor({ state: 'visible', timeout: 10000 });
      assert.match(await alertBanner.innerText(), /blocked the secure session cookie/i);
      assert.equal(
        await passwordInput.inputValue(),
        iframeUserPassword,
        'Password must not be erased when session cookie confirmation fails'
      );

      // (g) Real end-to-end login with initial HTTP 200 cold-start warmup.html -> automatically retries
      //     past warmup HTML without showing "unexpected server response", accepts __Host-vajra_session;
      //     Partitioned, and loads the authenticated dashboard!
      latestLoginSetCookieRedacted = '';
      interceptMode = 'WARMUP_ONCE';
      warmupInterceptedCount = 0;
      loginDispatchCount = 0;
      await signInBtn.click();
      await frame.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 12000 });
      assert.equal(warmupInterceptedCount, 1, 'Expected initial login attempt to hit warmup HTML');
      assert.equal(
        loginDispatchCount,
        2,
        'Expected automatic retry after 200 OK warmup HTML to succeed on second attempt'
      );
      assert.match(latestLoginSetCookieRedacted, /__Host-vajra_session=\[REDACTED\]/);
      assert.match(latestLoginSetCookieRedacted, /SameSite=None/i);
      assert.match(latestLoginSetCookieRedacted, /Secure/i);
      assert.match(latestLoginSetCookieRedacted, /Partitioned/i);

      // (h) Navigate & reload parent+iframe -> session restores automatically via /api/auth/me
      await frame.getByRole('button', { name: 'Devices' }).first().click();
      await frame.getByRole('heading', { name: 'Devices' }).first().waitFor({
        state: 'visible',
        timeout: 5000,
      });

      await hostPage.reload({ waitUntil: 'domcontentloaded' });
      await frame.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });

      // (i) Sign out behind the reverse proxy -> POST /api/auth/logout returns 200 (no CSRF_ORIGIN_MISMATCH),
      //     returns to login screen, and reload remains signed out
      let logoutStatus = 0;
      hostPage.on('response', (res) => {
        if (res.url().endsWith('/api/auth/logout')) {
          logoutStatus = res.status();
        }
      });

      await frame.getByRole('button', { name: 'Settings' }).first().click();
      await frame.getByRole('button', { name: 'Sign Out', exact: true }).click();
      await signInBtn.waitFor({ state: 'visible', timeout: 10000 });
      assert.equal(logoutStatus, 200, 'Expected POST /api/auth/logout to succeed with 200 behind reverse proxy');

      await hostPage.reload({ waitUntil: 'domcontentloaded' });
      await signInBtn.waitFor({ state: 'visible', timeout: 10000 });

      await iframeContext.close();
    } finally {
      if (iframeBrowser) {
        await iframeBrowser.close().catch(() => {});
      }
      if (parentServer) {
        await new Promise<void>((resolve) => parentServer!.close(() => resolve()));
      }
      await new Promise<void>((resolve) => proxyServer.close(() => resolve()));
    }
  });
});

