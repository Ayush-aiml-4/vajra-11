/**
 * VAJRA — Prompt 0005 UI/UX Abstraction & Security Language Verification Suite
 *
 * Verifies:
 * 1. Primary user-facing UI files (src/App.tsx, src/components/VajraUiPrimitives.tsx, src/components/securityCopy.ts)
 *    never leak internal engineering labels ("Prompt 000", "IMPLEMENTED", "MOCKED", "PLANNED",
 *    "Plane 1", "Plane 2", "Prisma", "PostgreSQL", "Argon2id", "AES-256-GCM", "/api/health").
 * 2. Human-friendly event translation (translateAuditEventToHuman) converts internal event codes
 *    into calm, intelligible consumer/prosumer security descriptions.
 * 3. ThreatCheck URL preview (evaluateUrlSafetyPreview) identifies deceptive links and never claims
 *    "100% safe".
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  translateAuditEventToHuman,
  evaluateUrlSafetyPreview,
  formatDeviceLifecycleLabel,
} from '../src/components/securityCopy.ts';

describe('VAJRA Prompt 0005 UI/UX Abstraction & Product Copy Suite', () => {
  it('User-facing UI source contains zero internal engineering stage or algorithm jargon', () => {
    const appSource = fs.readFileSync(path.resolve(process.cwd(), 'src/App.tsx'), 'utf8');
    const primitivesSource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/VajraUiPrimitives.tsx'),
      'utf8'
    );
    const copySource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/securityCopy.ts'),
      'utf8'
    );

    const combinedUiText = `${appSource}\n${primitivesSource}\n${copySource}`;

    const prohibitedUiStrings = [
      'Prompt 0001',
      'Prompt 0002',
      'Prompt 0003',
      'Prompt 0004',
      'Prompt 0005',
      'Plane 1',
      'Plane 2',
      'Prisma',
      'PostgreSQL',
      'Argon2id',
      'AES-256-GCM',
      'Verify API Health',
      'FOUNDATION_MODULES',
      'PROHIBITED_CAPABILITIES',
      'CORE_SECURITY_INVARIANTS',
    ];

    for (const forbidden of prohibitedUiStrings) {
      assert.equal(
        combinedUiText.includes(forbidden),
        false,
        `Primary user-facing UI must not expose internal engineering term "${forbidden}"`
      );
    }
  });

  it('Translates internal audit codes into calm, human-readable activity items', () => {
    const enrolled = translateAuditEventToHuman('DEVICE_ENROLLED', new Date().toISOString(), {
      deviceName: 'ASUS TUF F16',
    });
    assert.equal(enrolled.title, 'ASUS TUF F16 is now protected');
    assert.equal(enrolled.category, 'Device');
    assert.equal(enrolled.severity, 'Healthy');

    const blockedLogin = translateAuditEventToHuman('LOGIN_FAILURE', new Date().toISOString());
    assert.equal(blockedLogin.title, 'Unrecognized sign-in blocked');
    assert.equal(blockedLogin.severity, 'Attention');

    const deviceState = formatDeviceLifecycleLabel('TRUSTED');
    assert.equal(deviceState.label, 'Protected');
    assert.equal(deviceState.tone, 'protected');
  });

  it('ThreatCheck preview evaluates URLs honestly and never claims 100% safe', () => {
    const safeCheck = evaluateUrlSafetyPreview('https://github.com/security');
    assert.equal(safeCheck.verdict, 'LOW RISK');
    assert.equal(safeCheck.summary.toLowerCase().includes('100% safe'), false);
    assert.equal(safeCheck.recommendation.toLowerCase().includes('100% safe'), false);

    const phishingCheck = evaluateUrlSafetyPreview(
      'http://198.51.100.42/login-verify/account-update'
    );
    assert.equal(phishingCheck.verdict, 'HIGH RISK');
    assert.ok(phishingCheck.signals.length >= 2);
  });

  it('Prompt 0006 centralized design tokens and brand palette are enforced across UI and HTML', () => {
    const htmlSource = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf8');
    const tokensSource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/styles/designTokens.ts'),
      'utf8'
    );
    const appSource = fs.readFileSync(path.resolve(process.cwd(), 'src/App.tsx'), 'utf8');
    const primitivesSource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/VajraUiPrimitives.tsx'),
      'utf8'
    );

    // Manrope and Cormorant Garamond serif wordmark fonts are loaded and cyberpunk/gaming fonts are absent
    assert.equal(htmlSource.includes('Manrope'), true);
    assert.equal(htmlSource.includes('Cormorant+Garamond'), true);
    for (const bannedFont of ['Orbitron', 'Rajdhani', 'Audiowide']) {
      assert.equal(htmlSource.includes(bannedFont), false);
    }

    // Core Prompt 0006 palette tokens are present
    for (const hex of [
      '#08090B',
      '#101216',
      '#15171C',
      '#25282E',
      '#F4F1EA',
      '#9499A3',
      '#646A74',
      '#C8A66A',
      '#75B798',
    ]) {
      assert.equal(
        tokensSource.includes(hex),
        true,
        `Design token ${hex} must be defined in src/styles/designTokens.ts`
      );
    }

    // Signature brand copy and serif wordmark are present, while design-system lockup specimens are removed from production UI
    assert.equal(primitivesSource.includes('PERSONAL SECURITY'), true);
    assert.equal(primitivesSource.includes('font-wordmark'), true);
    assert.equal(primitivesSource.includes('01 · PRIMARY HORIZONTAL LOCKUP'), false);
    assert.equal(primitivesSource.includes('02 · COMPACT SIDEBAR LOCKUP'), false);
    assert.equal(primitivesSource.includes('03 · WORDMARK ALONE'), false);
    assert.equal(primitivesSource.includes('04 · EMBLEM + WORDMARK'), false);
    assert.equal(primitivesSource.includes('05 · SMALL-SIZE APPLICATION VERSION'), false);
    assert.equal(appSource.includes('Brand Typography & Lockup System'), false);
    assert.equal(appSource.includes('Your digital world is protected.'), true);
    assert.equal(appSource.includes('Know before you click.'), true);
  });

  it('Login page integrates cinematic Cloudinary background video with dark obsidian overlay, pointer-events isolation, and reduced-motion fallback', () => {
    const appSource = fs.readFileSync(path.resolve(process.cwd(), 'src/App.tsx'), 'utf8');
    const cssSource = fs.readFileSync(path.resolve(process.cwd(), 'src/index.css'), 'utf8');

    // Verify Cloudinary HTTPS URL configuration & video attributes on login page
    assert.equal(
      appSource.includes(
        'https://res.cloudinary.com/r67amuba/video/upload/v1791350761/Smooth_transition_between_scenes_20261007104851.mp4'
      ),
      true
    );
    assert.equal(appSource.includes('login-background-video'), true);
    assert.equal(appSource.includes('login-background-overlay'), true);
    assert.equal(appSource.includes('login-content'), true);
    assert.equal(appSource.includes('autoPlay'), true);
    assert.equal(appSource.includes('loop'), true);
    assert.equal(appSource.includes('muted'), true);
    assert.equal(appSource.includes('playsInline'), true);
    assert.equal(appSource.includes('onError={() => setLoginVideoFailed(true)}'), true);

    // Verify existing VAJRA login copy and structure remain intact
    assert.equal(appSource.includes('Quiet strength for your personal devices.'), true);
    assert.equal(appSource.includes('Verified Device Trust'), true);
    assert.equal(appSource.includes('Two-Step Protection'), true);
    assert.equal(appSource.includes('Sign In to VAJRA'), true);

    // Verify CSS positioning, pointer-events: none, object-fit: cover, dark overlay, and reduced-motion rule
    assert.equal(cssSource.includes('.login-background-video'), true);
    assert.equal(cssSource.includes('pointer-events: none;'), true);
    assert.equal(cssSource.includes('object-fit: cover;'), true);
    assert.equal(cssSource.includes('.login-background-overlay'), true);
    assert.equal(cssSource.includes('prefers-reduced-motion: reduce'), true);
  });

  it('Prompt 0009 integrates adaptive 5-layer VajraCinematicBackground, smoked obsidian surfaces, restrained semantic color system, and 01-04 Overview command center hierarchy', () => {
    const appSource = fs.readFileSync(path.resolve(process.cwd(), 'src/App.tsx'), 'utf8');
    const primitivesSource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/VajraUiPrimitives.tsx'),
      'utf8'
    );
    const tokensSource = fs.readFileSync(
      path.resolve(process.cwd(), 'src/styles/designTokens.ts'),
      'utf8'
    );
    const cssSource = fs.readFileSync(path.resolve(process.cwd(), 'src/index.css'), 'utf8');

    // 1. Verify VajraCinematicBackground and adaptive atmosphere presets
    assert.equal(primitivesSource.includes('VajraCinematicBackground'), true);
    assert.equal(appSource.includes('<VajraCinematicBackground'), true);
    assert.equal(appSource.includes('atmosphereIntensity'), true);
    assert.equal(tokensSource.includes('VAJRA_ATMOSPHERE_PRESETS'), true);

    // 2. Verify Prompt 0009 color system tokens (Warm Bronze #C79A5A, Smoked Obsidian #111216 / #151519, Semantic #78B999 / #D6A15A / #D06C64)
    for (const hex of ['#C79A5A', '#111216', '#151519', '#78B999', '#D6A15A', '#D06C64']) {
      assert.equal(
        tokensSource.includes(hex),
        true,
        `Prompt 0009 token ${hex} must be defined in src/styles/designTokens.ts`
      );
    }

    // 3. Verify 5-layer CSS atmosphere classes and smoked obsidian surface treatment
    assert.equal(cssSource.includes('.vajra-cinematic-root'), true);
    assert.equal(cssSource.includes('.vajra-cinematic-video'), true);
    assert.equal(cssSource.includes('.vajra-cinematic-scrim'), true);
    assert.equal(cssSource.includes('.vajra-cinematic-blend'), true);
    assert.equal(cssSource.includes('.vajra-surface-card'), true);
    assert.equal(cssSource.includes('.vajra-sidebar-surface'), true);
    assert.equal(cssSource.includes('.vajra-header-surface'), true);

    // 4. Verify 01-04 Overview command center hierarchy and editorial security advisories
    assert.equal(appSource.includes('01 · PROTECTION COMMAND CENTER'), true);
    assert.equal(appSource.includes('02 · PROTECTED DEVICES'), true);
    assert.equal(appSource.includes('03 · SECURITY ADVISORIES'), true);
    assert.equal(appSource.includes('04 · RECENT SECURITY TIMELINE'), true);
    assert.equal(appSource.includes('Security Advisories'), true);
    assert.equal(appSource.includes('All security systems nominal'), true);

    // 5. Verify Part 18 human-friendly Device Actions copy
    assert.equal(appSource.includes('Request Status Check'), true);
    assert.equal(appSource.includes('Check Protection Status'), true);
    assert.equal(appSource.includes('Mark Device for Review'), true);
    assert.equal(appSource.includes('End Active Sessions'), true);
  });
});
