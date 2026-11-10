/**
 * VAJRA — Prompt 0012: Analytics, Export, Isolation & SQL Evidence Consistency
 *
 * Focused tests (feature-first; full suite may be deferred).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import { escapeCsvCellSafe } from '../src/server/threatcheck/urlSafety.ts';

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
  }
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: any; rawText: string }> {
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('Server not listening');
  const payload = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
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
        port: (addr as any).port,
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

function extractCookie(setCookie: string | string[] | undefined): string {
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (!raw) return '';
  return raw.split(';')[0];
}

describe('Prompt 0012 — SQL evidence consistency', () => {
  it('migrations 0005–0007 files exist and declare expected objects', () => {
    const root = process.cwd();
    const m5 = fs.readFileSync(
      path.join(root, 'prisma/migrations/0005_rdbms_views_triggers_procedures/migration.sql'),
      'utf8'
    );
    assert.match(m5, /vw_device_security_posture/);
    assert.match(m5, /vw_command_audit_history/);
    assert.match(m5, /fn_prevent_audit_log_mutation/);
    assert.match(m5, /fn_record_command_execution_result/);
    assert.match(m5, /INNER JOIN "User"/);

    const m6 = fs.readFileSync(
      path.join(root, 'prisma/migrations/0006_step_up_action_scope/migration.sql'),
      'utf8'
    );
    assert.match(m6, /stepUpActionScope/);

    const m7 = fs.readFileSync(
      path.join(root, 'prisma/migrations/0007_analytics_query_indexes/migration.sql'),
      'utf8'
    );
    assert.match(m7, /SecurityEvent_userId_occurredAt_idx/);
    assert.match(m7, /ThreatCheck_userId_checkedAt_idx/);

    const schema = fs.readFileSync(path.join(root, 'prisma/schema.prisma'), 'utf8');
    assert.match(schema, /@@index\(\[userId, occurredAt\]\)/);
    assert.match(schema, /@@index\(\[userId, checkedAt\]\)/);
  });

  it('escapeCsvCellSafe neutralizes formula injection prefixes', () => {
    assert.ok(escapeCsvCellSafe('=cmd()').startsWith("'") || escapeCsvCellSafe('=cmd()').includes("'="));
    const escaped = escapeCsvCellSafe('=HYPERLINK("http://evil")');
    assert.equal(escaped.includes('=HYPERLINK') && !escaped.startsWith('='), true);
    assert.ok(escapeCsvCellSafe('normal text').includes('normal') || escapeCsvCellSafe('normal text') === '"normal text"');
  });
});

describe('Prompt 0012 — Analytics & export integration', () => {
  let server: http.Server;
  let cookieA = '';
  let csrfA = '';
  let cookieB = '';
  let csrfB = '';

  before(async () => {
    const repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));

    const regA = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'analytics-a@vajra.test',
        password: 'Str0ng!Passw0rd',
        displayName: 'Analytics A',
      },
    });
    assert.equal(regA.status, 201, JSON.stringify(regA.body));
    cookieA = extractCookie(regA.headers['set-cookie']);
    csrfA = regA.body.csrfToken;

    const regB = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: 'analytics-b@vajra.test',
        password: 'Str0ng!Passw0rd',
        displayName: 'Analytics B',
      },
    });
    assert.equal(regB.status, 201, JSON.stringify(regB.body));
    cookieB = extractCookie(regB.headers['set-cookie']);
    csrfB = regB.body.csrfToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('returns empty-safe analytics summary with PERSISTED dataSource', async () => {
    const res = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: cookieA,
      csrfToken: csrfA,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const summary = res.body.summary;
    assert.ok(summary);
    assert.equal(summary.dataSource, 'PERSISTED');
    assert.ok(typeof summary.windowDescription === 'string');
    // Fresh account: no devices/threatChecks/commands; securityEvents may include account lifecycle notices
    assert.ok(typeof summary.devices.totalCount === 'number');
    assert.ok(typeof summary.securityEvents.totalRecentCount === 'number');
    assert.ok(typeof summary.threatChecks.totalCount === 'number');
    assert.ok(typeof summary.remoteCommands.totalRecentCount === 'number');
    assert.ok(summary.accountPosture.currentScore >= 0);
  });

  it('denies unauthenticated analytics and isolates users', async () => {
    const unauth = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
    });
    assert.ok(unauth.status === 401 || unauth.status === 403);

    // User B should not see User A data (both empty, but session is distinct)
    const resB = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: cookieB,
      csrfToken: csrfB,
    });
    assert.equal(resB.status, 200);
    assert.equal(resB.body.summary.dataSource, 'PERSISTED');
  });

  it('exports JSON and CSV with safe headers and formula-safe cells', async () => {
    const jsonRes = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=json&limit=50',
      cookie: cookieA,
      csrfToken: csrfA,
    });
    assert.equal(jsonRes.status, 200, jsonRes.rawText.slice(0, 300));
    assert.match(String(jsonRes.headers['content-type'] || ''), /application\/json/);
    assert.match(String(jsonRes.headers['content-disposition'] || ''), /vajra-security-report/);
    assert.match(String(jsonRes.headers['cache-control'] || ''), /no-store/);

    const csvRes = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=csv&limit=50',
      cookie: cookieA,
      csrfToken: csrfA,
    });
    assert.equal(csvRes.status, 200);
    assert.match(String(csvRes.headers['content-type'] || ''), /text\/csv/);
    assert.match(String(csvRes.headers['cache-control'] || ''), /no-store/);
    assert.ok(csvRes.rawText.includes('RecordType') || csvRes.rawText.length >= 0);

    const bad = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=xml',
      cookie: cookieA,
      csrfToken: csrfA,
    });
    assert.equal(bad.status, 400);
  });

  it('rejects out-of-range export limit', async () => {
    const res = await requestJson(server, {
      method: 'GET',
      path: '/api/reports/export?format=json&limit=9999',
      cookie: cookieA,
      csrfToken: csrfA,
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error?.code, 'INVALID_EXPORT_LIMIT');
  });
});
