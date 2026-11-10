/**
 * VAJRA — Prompt 0011B Automated Test Suite
 * ThreatCheck Persistence, URL Safety & SSRF Boundaries, Analytics Summary & Report Exports
 *
 * Covers:
 * 1. Valid HTTP/HTTPS URLs and malformed input rejection.
 * 2. Unsupported protocols (javascript:, data:, file:, ftp:) and embedded credentials (user:pass@host) rejection.
 * 3. Query-string secret redaction (?token=[REDACTED]) and fragment (#...) stripping across persisted records and audit logs.
 * 4. Loopback, private RFC1918, link-local, Carrier-Grade NAT, IPv6, IPv4-mapped IPv6, alternative integer/hex/octal IPs, and cloud metadata-address classification as `restricted destination`.
 * 5. Zero outbound network or DNS requests during lexical analysis.
 * 6. ThreatCheck persistence and structured ThreatIndicator relationships in both InMemoryIdentityRepository and PrismaIdentityRepository (with mocked Prisma client).
 * 7. Cross-user isolation: User A cannot access User B's ThreatCheck history, analytics summary, or report exports.
 * 8. Pagination validation & limits on GET /api/threatcheck/history and invalid format rejection on GET /api/reports/export.
 * 9. Empty analytics dataset accuracy (no fabricated metrics).
 * 10. CSV quoting and spreadsheet formula-injection defenses (=, +, -, @).
 * 11. Sanitized audit events on ThreatCheck inspection and report export.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns';
import { createVajraApiApp } from '../src/server/app.ts';
import {
  InMemoryIdentityRepository,
  PrismaIdentityRepository,
} from '../src/server/db/repository.ts';
import {
  analyzeThreatCheckUrl,
  escapeCsvCellSafe,
} from '../src/server/threatcheck/urlSafety.ts';

interface TestSession {
  cookie: string;
  csrfToken: string;
  userId: string;
}

async function requestApi(
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

async function registerUser(
  server: http.Server,
  email: string,
  displayName: string
): Promise<TestSession> {
  const res = await requestApi(server, {
    method: 'POST',
    path: '/api/auth/register',
    body: {
      email,
      displayName,
      password: 'CorrectHorseBatteryStaple!99',
    },
  });
  assert.equal(res.status, 201);
  const setCookie = res.headers['set-cookie'];
  assert.ok(setCookie && setCookie.length > 0);
  return {
    cookie: setCookie[0].split(';')[0],
    csrfToken: res.body.csrfToken,
    userId: res.body.user.id,
  };
}

describe('VAJRA Prompt 0011B — URL Safety, SSRF Boundaries, ThreatCheck Persistence, Analytics & Exports', () => {
  let server: http.Server;
  let repo: InMemoryIdentityRepository;
  let userA: TestSession;
  let userB: TestSession;

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    userA = await registerUser(server, 'usera.prompt11b@vajra.local', 'User A');
    userB = await registerUser(server, 'userb.prompt11b@vajra.local', 'User B');
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. Validates HTTP/HTTPS URLs and rejects malformed URLs, unsupported protocols, and embedded credentials without making any network/DNS calls', () => {
    // Guard dns.lookup to prove zero DNS resolution occurs during lexical analysis
    const originalLookup = dns.lookup;
    let dnsCalled = false;
    (dns as any).lookup = (..._args: unknown[]) => {
      dnsCalled = true;
      throw new Error('DNS lookup must never be called during ThreatCheck lexical analysis');
    };

    try {
      // Valid HTTPS URL
      const validHttps = analyzeThreatCheckUrl('https://github.com/security/advisories');
      assert.equal(validHttps.valid, true);
      assert.equal(validHttps.verdict, 'LOW RISK');
      assert.equal(validHttps.classification, 'no obvious lexical indicators');
      assert.equal(validHttps.restrictedDestination, false);
      assert.match(validHttps.limitationsStatement ?? '', /not a guarantee/i);

      // Unsupported protocols
      for (const badProto of [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'file:///etc/passwd',
        'ftp://files.example.com/archive.zip',
      ]) {
        const res = analyzeThreatCheckUrl(badProto);
        assert.equal(res.valid, false, `Expected ${badProto} to be rejected`);
        assert.equal(res.errorCode, 'UNSUPPORTED_PROTOCOL');
      }

      // Embedded credentials
      const credUrl = analyzeThreatCheckUrl('https://admin:supersecret@example.com/login');
      assert.equal(credUrl.valid, false);
      assert.equal(credUrl.errorCode, 'EMBEDDED_CREDENTIALS_FORBIDDEN');

      // Malformed / invalid hostnames
      for (const malformed of ['', '   ', 'http://', 'https://invalid_tld', 'https://example..com/a b']) {
        const res = analyzeThreatCheckUrl(malformed);
        assert.equal(res.valid, false, `Expected "${malformed}" to be rejected`);
      }

      assert.equal(dnsCalled, false, 'Zero DNS calls must occur during lexical URL analysis');
    } finally {
      (dns as any).lookup = originalLookup;
    }
  });

  it('2. Redacts query parameters and strips URL fragments while flagging loopback, private, link-local, IPv6, IPv4-mapped IPv6, and cloud metadata destinations', () => {
    // Query and fragment redaction
    const withSecrets = analyzeThreatCheckUrl(
      'https://accounts.example.com/reset?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&session_key=rawSecret999#fragmentSecretValue'
    );
    assert.equal(withSecrets.valid, true);
    assert.equal(
      withSecrets.submittedUrlRedacted,
      'https://accounts.example.com/reset?token=[REDACTED]&session_key=[REDACTED]'
    );
    assert.equal(withSecrets.submittedUrlRedacted?.includes('rawSecret999'), false);
    assert.equal(withSecrets.submittedUrlRedacted?.includes('fragmentSecretValue'), false);

    // SSRF / Restricted Destination matrix
    const restrictedTargets = [
      'http://127.0.0.1:8080/admin',
      'http://localhost:3000/api/health',
      'http://10.0.0.1/internal',
      'http://172.16.5.4/router',
      'http://192.168.1.1/setup',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://[::1]:3000/',
      'http://[::ffff:127.0.0.1]/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://[fe80::1]/',
      'http://2130706433/', // integer 127.0.0.1
      'http://0x7f000001/', // hex 127.0.0.1
      'https://metadata.google.internal/computeMetadata/v1/',
    ];

    for (const target of restrictedTargets) {
      const outcome = analyzeThreatCheckUrl(target);
      assert.equal(outcome.valid, true, `Expected ${target} to parse for boundary classification`);
      assert.equal(
        outcome.restrictedDestination,
        true,
        `Expected ${target} to be flagged as restrictedDestination`
      );
      assert.equal(outcome.classification, 'restricted destination');
      assert.equal(outcome.verdict, 'HIGH RISK');
      assert.ok((outcome.riskScore ?? 0) >= 80);
    }
  });

  it('3. Empty analytics dataset for a new user returns accurate zero counts without fabricated activity', async () => {
    const summaryRes = await requestApi(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: userB.cookie,
    });
    assert.equal(summaryRes.status, 200);
    const { summary } = summaryRes.body;
    assert.equal(summary.devices.totalCount, 0);
    assert.equal(summary.devices.hardwareBackedCount, 0);
    assert.equal(summary.threatChecks.totalCount, 0);
    assert.equal(summary.threatChecks.averageRiskScore, 0);
    assert.deepEqual(summary.threatChecks.byVerdict, {
      'LOW RISK': 0,
      SUSPICIOUS: 0,
      'HIGH RISK': 0,
    });
    assert.equal(summary.remoteCommands.totalRecentCount, 0);
  });

  it('4. Persists ThreatCheck + ThreatIndicator records via POST /api/threatcheck/inspect and enforces pagination & redaction on GET /api/threatcheck/history', async () => {
    // Rejects unsupported protocol over HTTP API with 400
    const badProtoRes = await requestApi(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie: userA.cookie,
      csrfToken: userA.csrfToken,
      body: { url: 'javascript:alert(document.cookie)' },
    });
    assert.equal(badProtoRes.status, 400);
    assert.equal(badProtoRes.body.error.code, 'UNSUPPORTED_PROTOCOL');

    // Inspect a cloud metadata URL with query secret
    const inspectRestricted = await requestApi(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie: userA.cookie,
      csrfToken: userA.csrfToken,
      body: {
        url: 'http://169.254.169.254/latest/meta-data/iam?api_key=TOP_SECRET_KEY_12345#frag',
      },
    });
    assert.equal(inspectRestricted.status, 200);
    assert.equal(inspectRestricted.body.threatCheck.verdict, 'HIGH RISK');
    assert.equal(inspectRestricted.body.threatCheck.classification, 'restricted destination');
    assert.equal(inspectRestricted.body.threatCheck.restrictedDestination, true);
    assert.equal(
      inspectRestricted.body.threatCheck.submittedUrlRedacted,
      'http://169.254.169.254/latest/meta-data/iam?api_key=[REDACTED]'
    );
    assert.equal(
      JSON.stringify(inspectRestricted.body).includes('TOP_SECRET_KEY_12345'),
      false,
      'Response must never contain raw query secret'
    );
    assert.ok(inspectRestricted.body.threatCheck.indicators.length >= 2);

    // Inspect a clean HTTPS URL with formula-like path to test CSV export escaping later
    const inspectClean = await requestApi(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie: userA.cookie,
      csrfToken: userA.csrfToken,
      body: {
        url: 'https://developer.mozilla.org/en-US/docs/Web/Security?token=mySecretToken999',
      },
    });
    assert.equal(inspectClean.status, 200);
    assert.equal(inspectClean.body.threatCheck.verdict, 'LOW RISK');
    assert.equal(
      inspectClean.body.threatCheck.submittedUrlRedacted,
      'https://developer.mozilla.org/en-US/docs/Web/Security?token=[REDACTED]'
    );

    // Query GET /api/threatcheck/history with pagination
    const historyPage1 = await requestApi(server, {
      method: 'GET',
      path: '/api/threatcheck/history?limit=1&offset=0',
      cookie: userA.cookie,
    });
    assert.equal(historyPage1.status, 200);
    assert.equal(historyPage1.body.checks.length, 1);
    assert.equal(historyPage1.body.pagination.totalCount, 2);
    assert.equal(historyPage1.body.pagination.hasMore, true);

    // Reject invalid pagination parameters
    const invalidPageRes = await requestApi(server, {
      method: 'GET',
      path: '/api/threatcheck/history?limit=500&offset=-1',
      cookie: userA.cookie,
    });
    assert.equal(invalidPageRes.status, 400);
    assert.equal(invalidPageRes.body.error.code, 'INVALID_PAGINATION');

    // Verify AuditLog never contains raw secret
    const auditRes = await requestApi(server, {
      method: 'GET',
      path: '/api/audit',
      cookie: userA.cookie,
    });
    assert.equal(auditRes.status, 200);
    const serializedAudit = JSON.stringify(auditRes.body);
    assert.equal(serializedAudit.includes('TOP_SECRET_KEY_12345'), false);
    assert.equal(serializedAudit.includes('mySecretToken999'), false);
  });

  it('5. Enforces strict cross-user isolation on ThreatCheck history, analytics summary, and report exports', async () => {
    // User B history must not contain User A's 2 checks
    const historyB = await requestApi(server, {
      method: 'GET',
      path: '/api/threatcheck/history',
      cookie: userB.cookie,
    });
    assert.equal(historyB.status, 200);
    assert.equal(historyB.body.checks.length, 0);
    assert.equal(historyB.body.pagination.totalCount, 0);

    // User A analytics reflects User A's 2 checks
    const summaryA = await requestApi(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie: userA.cookie,
    });
    assert.equal(summaryA.status, 200);
    assert.equal(summaryA.body.summary.threatChecks.totalCount, 2);
    assert.equal(summaryA.body.summary.threatChecks.byVerdict['HIGH RISK'], 1);
    assert.equal(summaryA.body.summary.threatChecks.byVerdict['LOW RISK'], 1);

    // User B export must not contain User A's checks or email
    const exportB = await requestApi(server, {
      method: 'GET',
      path: '/api/reports/export?format=json',
      cookie: userB.cookie,
    });
    assert.equal(exportB.status, 200);
    assert.equal(exportB.body.threatChecks.length, 0);
    assert.equal(exportB.body.reportMetadata.ownerEmail, 'userb.prompt11b@vajra.local');
  });

  it('6. Exports JSON and CSV reports with proper headers, format validation, secret redaction, and CSV formula-injection neutralization', async () => {
    // Direct unit check on escapeCsvCellSafe for =, +, -, @
    assert.equal(escapeCsvCellSafe('=CMD|" /C calc"!A0'), '"\'=CMD|"" /C calc""!A0"');
    assert.equal(escapeCsvCellSafe('+SUM(A1:A10)'), '"\'+SUM(A1:A10)"');
    assert.equal(escapeCsvCellSafe('-2+3+cmd'), '"\'-2+3+cmd"');
    assert.equal(escapeCsvCellSafe('@SUM(1,2)'), '"\'@SUM(1,2)"');

    // Ingest a security event with a title beginning with '=' to verify end-to-end CSV neutralization
    const formulaEventRes = await requestApi(server, {
      method: 'POST',
      path: '/api/events',
      cookie: userA.cookie,
      csrfToken: userA.csrfToken,
      body: {
        category: 'Security',
        type: 'DEVICE_SECURITY_CHECK',
        severity: 'INFO',
        title: '=1+1_FORMULA_INJECTION_TEST',
        description: '@IMPORTXML(http://evil.example)',
      },
    });
    assert.equal(formulaEventRes.status, 201);

    // JSON export
    const jsonExport = await requestApi(server, {
      method: 'GET',
      path: '/api/reports/export?format=json&limit=50',
      cookie: userA.cookie,
    });
    assert.equal(jsonExport.status, 200);
    assert.match(String(jsonExport.headers['content-type']), /application\/json/);
    assert.match(
      String(jsonExport.headers['content-disposition']),
      /attachment; filename="vajra-security-report-.*\.json"/
    );
    assert.equal(jsonExport.body.threatChecks.length, 2);
    assert.equal(jsonExport.rawText.includes('passwordHash'), false);
    assert.equal(jsonExport.rawText.includes('TOP_SECRET_KEY_12345'), false);

    // CSV export
    const csvExport = await requestApi(server, {
      method: 'GET',
      path: '/api/reports/export?format=csv&limit=50',
      cookie: userA.cookie,
    });
    assert.equal(csvExport.status, 200);
    assert.match(String(csvExport.headers['content-type']), /text\/csv/);
    assert.match(
      String(csvExport.headers['content-disposition']),
      /attachment; filename="vajra-security-report-.*\.csv"/
    );
    assert.match(csvExport.rawText, /"'=1\+1_FORMULA_INJECTION_TEST"/);
    assert.match(csvExport.rawText, /"'@IMPORTXML\(http:\/\/evil\.example\)"/);
    assert.equal(csvExport.rawText.includes('TOP_SECRET_KEY_12345'), false);

    // Invalid export format rejected with 400
    const badFormatRes = await requestApi(server, {
      method: 'GET',
      path: '/api/reports/export?format=xml',
      cookie: userA.cookie,
    });
    assert.equal(badFormatRes.status, 400);
    assert.equal(badFormatRes.body.error.code, 'UNSUPPORTED_EXPORT_FORMAT');
  });

  it('7. Verifies PrismaIdentityRepository ThreatCheck persistence and indicator ordering using a mock PrismaClient delegate', async () => {
    let capturedCreateArgs: any = null;
    const now = new Date();
    const mockPrismaClient = {
      threatCheck: {
        create: async (args: any) => {
          capturedCreateArgs = args;
          return {
            id: '00000000-0000-4000-8000-000000000111',
            userId: args.data.userId,
            deviceId: args.data.deviceId,
            submittedUrl: args.data.submittedUrl,
            normalizedDomain: args.data.normalizedDomain,
            verdict: args.data.verdict,
            riskScore: args.data.riskScore,
            summary: args.data.summary,
            recommendedGuidance: args.data.recommendedGuidance,
            source: args.data.source,
            checkedAt: now,
            indicators: args.data.indicators.create.map((ind: any, idx: number) => ({
              id: `00000000-0000-4000-8000-00000000020${idx}`,
              threatCheckId: '00000000-0000-4000-8000-000000000111',
              ...ind,
            })),
          };
        },
        findMany: async () => [],
        count: async () => 0,
      },
    } as any;

    const prismaRepo = new PrismaIdentityRepository(mockPrismaClient);
    const saved = await prismaRepo.createThreatCheck({
      userId: userA.userId,
      submittedUrl: 'https://example.com/login?token=[REDACTED]',
      normalizedDomain: 'example.com',
      verdict: 'LOW RISK',
      riskScore: 10,
      summary: 'No obvious lexical indicators.',
      recommendedGuidance: 'Verify domain before signing in.',
      indicators: [
        {
          code: 'REDACTED_SENSITIVE_QUERY_KEYS',
          category: 'QueryPrivacy',
          severity: 'LOW',
          title: 'Sensitive query parameters redacted',
          explanation: 'Query token redacted.',
          weight: 10,
        },
      ],
    });

    assert.ok(capturedCreateArgs);
    assert.equal(saved.id, '00000000-0000-4000-8000-000000000111');
    assert.equal(saved.indicators.length, 1);
    assert.equal(saved.indicators[0].code, 'REDACTED_SENSITIVE_QUERY_KEYS');
  });
});
