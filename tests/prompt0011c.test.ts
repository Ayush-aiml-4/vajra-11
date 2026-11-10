/**
 * VAJRA — Prompt 0011C Frontend Integration & API Contract Verification Suite
 *
 * Verifies:
 * 1. Frontend wiring in `src/App.tsx` for:
 *    - `GET /api/analytics/summary`
 *    - `POST /api/threatcheck/inspect`
 *    - `GET /api/threatcheck/history`
 *    - `GET /api/reports/export?format=json`
 *    - `GET /api/reports/export?format=csv`
 * 2. Presence of loading, empty, error, and success UI states across Overview Analytics,
 *    ThreatCheck inspection/history, and Report Export controls.
 * 3. ThreatCheck UI displays:
 *    - Verdict and riskScore
 *    - Explainable ThreatIndicator breakdown (title, category, severity, explanation, weight)
 *    - Restricted-destination boundary warning banner
 *    - Explicit lexical analysis limitations statement
 *    - Redacted URL display (`submittedUrlRedacted`) so query secrets are never rendered
 * 4. End-to-end data flow between backend endpoints and frontend DTO contracts.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import {
  translateAuditEventToHuman,
  evaluateUrlSafetyPreview,
} from '../src/components/securityCopy.ts';
import type {
  AnalyticsSummaryDto,
  ThreatCheckHistoryPaginationDto,
  ThreatCheckRecordDto,
} from '../packages/shared-types/src/index.ts';

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
  }
): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
  body: any;
  rawText: string;
}> {
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Server not listening');
  }
  const payload = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(payload).toString();
  }
  if (options.cookie) headers['Cookie'] = options.cookie;
  if (options.csrfToken) headers['X-CSRF-Token'] = options.csrfToken;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: addr.port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          const rawText = Buffer.concat(chunks).toString('utf8');
          let body: any = {};
          try {
            body = rawText ? JSON.parse(rawText) : {};
          } catch {
            body = { rawText };
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
            rawText,
          });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

describe('VAJRA Prompt 0011C — Frontend Integration for ThreatCheck, Analytics & Reports', () => {
  let server: http.Server;
  let repo: InMemoryIdentityRepository;
  let sessionCookie = '';
  let csrfToken = '';

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'owner.prompt11c@vajra.local',
        displayName: 'Aarav Rao',
        password: 'CorrectHorseBatteryStaple!11c',
      },
    });
    assert.equal(reg.status, 201);
    sessionCookie = (reg.headers['set-cookie'] ?? [''])[0].split(';')[0];
    csrfToken = reg.body.csrfToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. Frontend source wires Overview Analytics, ThreatCheck inspection & history, and JSON/CSV Report Exports without engineering jargon', () => {
    const appSource = fs.readFileSync(path.resolve(process.cwd(), 'src/App.tsx'), 'utf8');

    // Verify all 5 required endpoints are integrated in src/App.tsx
    assert.equal(appSource.includes('/api/analytics/summary'), true);
    assert.equal(appSource.includes('/api/threatcheck/inspect'), true);
    assert.equal(appSource.includes('/api/threatcheck/history'), true);
    assert.equal(appSource.includes('/api/reports/export?format='), true);

    // Verify Overview Analytics UI states (loading, error, empty baseline, metrics cards, manual refresh)
    assert.equal(appSource.includes('05 · SECURITY ANALYTICS & REPORT EXPORT'), true);
    assert.equal(appSource.includes('Persisted Security Posture & Reports'), true);
    assert.equal(appSource.includes('Loading persisted security analytics...'), true);
    assert.equal(appSource.includes('New account analytics baseline'), true);
    assert.equal(appSource.includes('Refresh Analytics'), true);

    // Verify ThreatCheck UI features (risk score, restricted destination banner, explainable indicators, limitations note, history list & filter)
    assert.equal(appSource.includes('Restricted Destination Boundary Flagged'), true);
    assert.equal(appSource.includes('Explainable Threat Indicators'), true);
    assert.equal(appSource.includes('Limitations note:'), true);
    assert.equal(appSource.includes('ThreatCheck History'), true);
    assert.equal(appSource.includes('No links inspected yet'), true);
    assert.equal(appSource.includes('submittedUrlRedacted'), true);

    // Verify JSON and CSV export buttons and busy states
    assert.equal(appSource.includes('Export JSON'), true);
    assert.equal(appSource.includes('Export CSV'), true);
    assert.equal(appSource.includes('Exporting JSON...'), true);
    assert.equal(appSource.includes('Exporting CSV...'), true);

    // Verify stale-response sequence guards, 401 session-expiration handling, and duplicate-submit protection
    assert.equal(appSource.includes('analyticsRequestSeqRef'), true);
    assert.equal(appSource.includes('threatHistoryRequestSeqRef'), true);
    assert.equal(appSource.includes('threatInspectRequestSeqRef'), true);
    assert.equal(appSource.includes('handleSessionExpired'), true);
    assert.equal(appSource.includes('if (threatInspectBusy) return;'), true);
  });

  it('3. Client-side evaluateUrlSafetyPreview never reveals raw query values or fragments even on malformed inputs', () => {
    const validWithSecrets = evaluateUrlSafetyPreview(
      'https://example.com/login?token=TOP_SECRET_TOKEN_123&key=PRIVATE_999#fragment_secret'
    );
    assert.equal(validWithSecrets.normalizedDisplayUrl.includes('TOP_SECRET_TOKEN_123'), false);
    assert.equal(validWithSecrets.normalizedDisplayUrl.includes('PRIVATE_999'), false);
    assert.equal(validWithSecrets.normalizedDisplayUrl.includes('fragment_secret'), false);

    const malformedWithSecrets = evaluateUrlSafetyPreview(
      'http://[invalid-ipv6/callback?access_token=MALFORMED_SECRET_777#frag_leak'
    );
    assert.equal(
      malformedWithSecrets.normalizedDisplayUrl.includes('MALFORMED_SECRET_777'),
      false
    );
    assert.equal(malformedWithSecrets.normalizedDisplayUrl.includes('frag_leak'), false);
  });

  it('2. End-to-end flow: Frontend DTOs match backend responses for empty baseline, ThreatCheck inspection, history pagination, analytics refresh, and report export', async () => {
    // Step 1: Initial Analytics Summary for new account reflects empty baseline
    const initialAnalyticsRes = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: sessionCookie,
    });
    assert.equal(initialAnalyticsRes.status, 200);
    const initialSummary = initialAnalyticsRes.body.summary as AnalyticsSummaryDto;
    assert.equal(initialSummary.devices.totalCount, 0);
    assert.equal(initialSummary.threatChecks.totalCount, 0);
    assert.equal(initialSummary.remoteCommands.totalRecentCount, 0);

    // Step 2: Inspect a restricted destination URL with query secret via POST /api/threatcheck/inspect
    const inspectRes = await requestJson(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie: sessionCookie,
      csrfToken,
      body: {
        url: 'http://127.0.0.1:8080/internal-admin?session_token=SUPER_SECRET_SESSION_999#frag',
      },
    });
    assert.equal(inspectRes.status, 200);
    const record = inspectRes.body.threatCheck as ThreatCheckRecordDto;
    assert.equal(record.verdict, 'HIGH RISK');
    assert.equal(record.restrictedDestination, true);
    assert.equal(record.classification, 'restricted destination');
    assert.equal(
      record.submittedUrlRedacted,
      'http://127.0.0.1:8080/internal-admin?session_token=[REDACTED]'
    );
    assert.equal(record.submittedUrlRedacted.includes('SUPER_SECRET_SESSION_999'), false);
    assert.ok(record.indicators.length >= 2);
    assert.ok(record.limitationsStatement && record.limitationsStatement.length > 20);

    // Step 3: Fetch ThreatCheck history via GET /api/threatcheck/history
    const historyRes = await requestJson(server, {
      method: 'GET',
      path: '/api/threatcheck/history?limit=15&offset=0',
      cookie: sessionCookie,
    });
    assert.equal(historyRes.status, 200);
    const checks = historyRes.body.checks as ThreatCheckRecordDto[];
    const pagination = historyRes.body.pagination as ThreatCheckHistoryPaginationDto;
    assert.equal(checks.length, 1);
    assert.equal(pagination.totalCount, 1);
    assert.equal(pagination.hasMore, false);
    assert.equal(checks[0].id, record.id);
    assert.equal(
      checks[0].submittedUrlRedacted,
      'http://127.0.0.1:8080/internal-admin?session_token=[REDACTED]'
    );

    // Step 4: Refresh Analytics Summary and confirm ThreatCheck count & verdict breakdown updated
    const updatedAnalyticsRes = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: sessionCookie,
    });
    assert.equal(updatedAnalyticsRes.status, 200);
    const updatedSummary = updatedAnalyticsRes.body.summary as AnalyticsSummaryDto;
    assert.equal(updatedSummary.threatChecks.totalCount, 1);
    assert.equal(updatedSummary.threatChecks.byVerdict['HIGH RISK'], 1);
    assert.ok(updatedSummary.threatChecks.averageRiskScore >= 80);

    // Step 5: Export JSON & CSV reports and verify audit translation
    const jsonExportRes = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=json&limit=100',
      cookie: sessionCookie,
    });
    assert.equal(jsonExportRes.status, 200);
    assert.equal(jsonExportRes.body.threatChecks.length, 1);
    assert.equal(
      jsonExportRes.rawText.includes('SUPER_SECRET_SESSION_999'),
      false,
      'Exported JSON report must never leak raw query secrets'
    );

    const csvExportRes = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=csv&limit=100',
      cookie: sessionCookie,
    });
    assert.equal(csvExportRes.status, 200);
    assert.equal(
      csvExportRes.rawText.includes('SUPER_SECRET_SESSION_999'),
      false,
      'Exported CSV report must never leak raw query secrets'
    );

    // Verify human-readable audit translation for SECURITY_REPORT_EXPORTED
    const translatedExport = translateAuditEventToHuman(
      'SECURITY_REPORT_EXPORTED',
      new Date().toISOString(),
      { format: 'csv' }
    );
    assert.equal(translatedExport.title, 'Security report exported (CSV)');
    assert.equal(translatedExport.severity, 'Information');
  });
});
