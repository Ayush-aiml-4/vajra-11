/**
 * VAJRA — Prompt 0050 Regression Suite: Sign-In, Reverse-Proxy HTTPS Session Cookies & CSRF Origin Validation
 *
 * Verifies:
 * 1. Local HTTP development requests issue `vajra_session` (`HttpOnly; SameSite=Lax; Path=/`, without `Secure`).
 * 2. Reverse-proxy HTTPS requests where an internal sidecar proxy rewrites `Host: localhost:3000` and
 *    `X-Forwarded-Proto: http` while preserving `Origin: https://...` and `X-Forwarded-Host` issue
 *    `__Host-vajra_session` with `HttpOnly; SameSite=None; Secure; Partitioned; Path=/`.
 * 3. Subsequent `GET /api/auth/me` and idle session token rotation preserve `__Host-vajra_session` +
 *    `SameSite=None; Secure; Partitioned` even when `Referrer-Policy: no-referrer` omits `Origin`/`Referer`.
 * 4. Authenticated state-changing requests (`POST /api/auth/logout`, `POST /api/auth/mfa/setup`) behind a
 *    local loopback reverse proxy accept matching `Origin` + `X-Forwarded-Host` + `X-CSRF-Token`, while
 *    still rejecting cross-origin (`Origin: https://evil.example`) and spoofed non-loopback `X-Forwarded-Host`.
 * 5. Invalid password (`401`), MFA challenge (`mfaRequired: true` with no premature session cookie),
 *    TOTP verification, `STEP_UP_REQUIRED` (`403`) enforcement, and logout session revocation remain intact.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { Request } from 'express';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import {
  isSecureRequest,
  requireAuthenticatedUser,
  PrincipalLevel,
  SESSION_COOKIE_PROD,
  SESSION_COOKIE_DEV,
  STEP_UP_SCOPES,
} from '../src/server/auth/middleware.ts';
import {
  generateSessionTokenPair,
  generateTotpCodeAtTime,
  hashSessionToken,
  SESSION_ROTATION_THRESHOLD_MS,
} from '../packages/security/src/node.ts';

const TEST_TOTP_KEY = 'prompt0050-totp-secret-key-32byt!';

interface RawHttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  setCookies: string[];
  body: any;
}

async function rawHttpRequest(
  port: number,
  options: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
  }
): Promise<RawHttpResponse> {
  const payload = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const reqHeaders: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers ?? {}),
  };
  if (payload !== undefined) {
    reqHeaders['Content-Type'] = 'application/json';
    reqHeaders['Content-Length'] = String(Buffer.byteLength(payload));
  }

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: options.method,
        path: options.path,
        headers: reqHeaders,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown = null;
          try {
            parsed = text ? JSON.parse(text) : null;
          } catch {
            parsed = { _raw: text };
          }
          const rawSetCookie = res.headers['set-cookie'];
          const setCookies = Array.isArray(rawSetCookie)
            ? rawSetCookie
            : typeof rawSetCookie === 'string'
              ? [rawSetCookie]
              : [];
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            setCookies,
            body: parsed,
          });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function extractCookiePair(setCookies: string[], cookieName: string): string {
  const match = setCookies.find((entry) => entry.startsWith(`${cookieName}=`));
  assert.ok(match, `Expected Set-Cookie for ${cookieName}, received: ${setCookies.map((c) => c.split('=')[0]).join(', ')}`);
  return match.split(';')[0] ?? '';
}

describe('Prompt 0050 — Reverse-proxy HTTPS cookies, CSRF origin validation & auth lifecycle', () => {
  let repository: InMemoryIdentityRepository;
  let server: http.Server;
  let port = 0;

  before(async () => {
    repository = new InMemoryIdentityRepository();
    const app = createVajraApiApp({
      repository,
      totpEncryptionKey: TEST_TOTP_KEY,
    });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    port = addr.port;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('issues local HTTP dev cookies (vajra_session, SameSite=Lax) on plain http://localhost requests', async () => {
    const email = 'local.http.0050@vajra.test';
    const password = 'Prompt0050-ValidPassword!';

    const regRes = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/register',
      headers: {
        Host: `localhost:${port}`,
        Origin: `http://localhost:${port}`,
      },
      body: {
        email,
        displayName: 'Local HTTP Owner',
        password,
      },
    });

    assert.equal(regRes.status, 201);
    const devCookieHeader = regRes.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE_DEV}=`));
    assert.ok(devCookieHeader, 'Expected vajra_session cookie on plain HTTP localhost');
    assert.match(devCookieHeader, /HttpOnly/i);
    assert.match(devCookieHeader, /SameSite=Lax/i);
    assert.doesNotMatch(devCookieHeader, /;\s*Secure/i);
    assert.doesNotMatch(devCookieHeader, /Partitioned/i);
  });

  it('issues __Host-vajra_session with SameSite=None; Secure; Partitioned when an internal HTTP reverse proxy forwards HTTPS Origin', async () => {
    const publicHost = 'ais-dev-vajra-preview.example.run.app';
    const publicOrigin = `https://${publicHost}`;
    const email = 'proxy.https.0050@vajra.test';
    const password = 'Prompt0050-ProxyPassword!';

    // 1. Register via reverse-proxy headers (Host rewritten to localhost:<port>, X-Forwarded-Proto overwritten to http)
    const regRes = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/register',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
      },
      body: {
        email,
        displayName: 'Proxy HTTPS Owner',
        password,
      },
    });
    assert.equal(regRes.status, 201);

    // 2. Wrong password returns 401 and sets NO session cookie
    const badLogin = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/login',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
      },
      body: {
        email,
        password: 'WrongPassword-12345!',
      },
    });
    assert.equal(badLogin.status, 401);
    assert.equal(badLogin.body?.error?.code, 'INVALID_CREDENTIALS');
    assert.equal(badLogin.body?.error?.message, 'Invalid credentials.');
    assert.equal(badLogin.setCookies.length, 0);

    // 3. Valid login issues __Host-vajra_session with SameSite=None; Secure; Partitioned; HttpOnly; Path=/
    const loginRes = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/login',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
      },
      body: {
        email,
        password,
      },
    });
    assert.equal(loginRes.status, 200);
    assert.equal(loginRes.body?.authenticated, true);
    assert.equal(loginRes.body?.mfaRequired, false);

    const prodSetCookie = loginRes.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE_PROD}=`));
    assert.ok(prodSetCookie, 'Expected __Host-vajra_session cookie on HTTPS Origin behind HTTP proxy');
    assert.match(prodSetCookie, /Path=\//);
    assert.match(prodSetCookie, /HttpOnly/i);
    assert.match(prodSetCookie, /SameSite=None/i);
    assert.match(prodSetCookie, /;\s*Secure/i);
    assert.match(prodSetCookie, /;\s*Partitioned/i);

    let activeCookiePair = extractCookiePair(loginRes.setCookies, SESSION_COOKIE_PROD);
    let activeCsrf = String(loginRes.body.csrfToken);

    // 4. Subsequent GET /api/auth/me without Origin or Referer (Referrer-Policy: no-referrer) restores session
    const meRes = await rawHttpRequest(port, {
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Cookie: activeCookiePair,
      },
    });
    assert.equal(meRes.status, 200);
    assert.equal(meRes.body?.authenticated, true);
    assert.equal(meRes.body?.user?.email, email);
    activeCsrf = String(meRes.body.csrfToken);

    // 5. Simulate idle session rotation (> 7.5 min) on a GET request without Origin/Referer:
    //    must rotate as __Host-vajra_session with SameSite=None; Secure; Partitioned (NOT downgrade to vajra_session!)
    const rawCurrentToken = decodeURIComponent(
      activeCookiePair.slice(`${SESSION_COOKIE_PROD}=`.length)
    );
    const latestSession = await repository.findSessionByTokenHash(
      hashSessionToken(rawCurrentToken)
    );
    assert.ok(latestSession);
    await repository.updateSessionActivityAndRotation({
      sessionId: latestSession.id,
      lastActiveAt: new Date(Date.now() - SESSION_ROTATION_THRESHOLD_MS - 5000),
      expiresAt: latestSession.expiresAt,
    });

    const rotatedMe = await rawHttpRequest(port, {
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Cookie: activeCookiePair,
      },
    });
    assert.equal(rotatedMe.status, 200);
    const rotatedSetCookie = rotatedMe.setCookies.find((c) =>
      c.startsWith(`${SESSION_COOKIE_PROD}=`)
    );
    assert.ok(rotatedSetCookie, 'Rotated cookie must stay __Host-vajra_session');
    assert.match(rotatedSetCookie, /SameSite=None/i);
    assert.match(rotatedSetCookie, /;\s*Secure/i);
    assert.match(rotatedSetCookie, /;\s*Partitioned/i);
    activeCookiePair = extractCookiePair(rotatedMe.setCookies, SESSION_COOKIE_PROD);
    activeCsrf = String(rotatedMe.headers['x-vajra-csrf-token'] ?? rotatedMe.body.csrfToken);

    // 6. Cross-origin state-changing request from attacker site is still rejected with 403 CSRF_ORIGIN_MISMATCH
    const evilLogout = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/logout',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: 'https://evil-attacker.example',
        Cookie: activeCookiePair,
        'X-CSRF-Token': activeCsrf,
      },
      body: { revokeAll: false },
    });
    assert.equal(evilLogout.status, 403);
    assert.equal(evilLogout.body?.error?.code, 'CSRF_ORIGIN_MISMATCH');

    // 7. Legitimate state-changing MFA setup + confirm + MFA challenge + step-up enforcement behind reverse proxy
    const mfaSetup = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/mfa/setup',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
        Cookie: activeCookiePair,
        'X-CSRF-Token': activeCsrf,
      },
      body: {},
    });
    assert.equal(mfaSetup.status, 200);
    const totpSecret = String(mfaSetup.body.secretBase32);
    assert.ok(totpSecret.length > 10);

    const mfaConfirm = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/mfa/verify',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
        Cookie: activeCookiePair,
        'X-CSRF-Token': activeCsrf,
      },
      body: { code: generateTotpCodeAtTime(totpSecret) },
    });
    assert.equal(mfaConfirm.status, 200);
    assert.equal(mfaConfirm.body?.totpEnabled, true);

    // Logout via reverse proxy succeeds (200) and clears __Host-vajra_session with Partitioned; Max-Age=0
    const logoutRes = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/logout',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
        Cookie: activeCookiePair,
        'X-CSRF-Token': activeCsrf,
      },
      body: { revokeAll: false },
    });
    assert.equal(logoutRes.status, 200);
    const clearProd = logoutRes.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE_PROD}=;`));
    assert.ok(clearProd, 'Expected __Host-vajra_session clear directive on logout');
    assert.match(clearProd, /Partitioned/i);
    assert.match(clearProd, /Max-Age=0/i);

    // Old session cookie is now revoked on the server
    const meAfterLogout = await rawHttpRequest(port, {
      method: 'GET',
      path: '/api/auth/me',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        Cookie: activeCookiePair,
      },
    });
    assert.equal(meAfterLogout.status, 401);

    // Password-only login for MFA-enabled user returns mfaRequired: true and sets NO session cookie
    const mfaChallenge = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/login',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
      },
      body: { email, password },
    });
    assert.equal(mfaChallenge.status, 200);
    assert.equal(mfaChallenge.body?.authenticated, false);
    assert.equal(mfaChallenge.body?.mfaRequired, true);
    assert.equal(mfaChallenge.setCookies.length, 0);

    // Completing login with valid TOTP issues __Host-vajra_session; Partitioned
    const mfaLogin = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/login',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
      },
      body: {
        email,
        password,
        totpCode: generateTotpCodeAtTime(totpSecret),
      },
    });
    assert.equal(mfaLogin.status, 200);
    assert.equal(mfaLogin.body?.authenticated, true);
    const mfaCookie = extractCookiePair(mfaLogin.setCookies, SESSION_COOKIE_PROD);
    const mfaCsrf = String(mfaLogin.body.csrfToken);

    // Verify step-up endpoint still enforces valid TOTP and grants scoped step-up without any bypass
    const badStepUp = await rawHttpRequest(port, {
      method: 'POST',
      path: '/api/auth/step-up',
      headers: {
        Host: `localhost:${port}`,
        'X-Forwarded-Host': publicHost,
        'X-Forwarded-Proto': 'http',
        Origin: publicOrigin,
        Cookie: mfaCookie,
        'X-CSRF-Token': mfaCsrf,
      },
      body: {
        totpCode: '000000',
        actionScope: STEP_UP_SCOPES.ENABLE_LOST_MODE,
      },
    });
    assert.equal(badStepUp.status, 401);
  });

  it('rejects spoofed X-Forwarded-Host when trust proxy is disabled and remote socket is NOT loopback', () => {
    const tokenPair = generateSessionTokenPair();
    const fakeReq = {
      method: 'POST',
      headers: {
        host: 'vajra.internal.example:3000',
        'x-forwarded-host': 'attacker.evil.example',
        origin: 'https://attacker.evil.example',
        'x-csrf-token': tokenPair.rawCsrfToken,
      },
      socket: {
        remoteAddress: '203.0.113.42',
      },
      app: {
        get: (key: string) => (key === 'trust proxy' ? false : undefined),
      },
      authContext: {
        principalLevel: PrincipalLevel.AUTHENTICATED_USER,
        user: {
          id: 'u-1',
          email: 'owner@vajra.test',
          displayName: 'Owner',
          passwordHash: 'hash',
          status: 'ACTIVE',
          mfaEnabled: false,
          totpSecretEncrypted: null,
          failedLoginCount: 0,
          lockedUntil: null,
          lastLoginAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        session: {
          id: 's-1',
          userId: 'u-1',
          tokenHash: tokenPair.sessionTokenHash,
          csrfTokenHash: tokenPair.csrfTokenHash,
          userAgent: null,
          ipAddress: '203.0.113.42',
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 600_000),
          absoluteExpiresAt: new Date(Date.now() + 3_600_000),
          revokedAt: null,
          stepUpVerifiedUntil: null,
          stepUpActionScope: null,
        },
      },
    } as unknown as Request;

    let capturedStatus = 200;
    let capturedJson: any = null;
    let nextCalled = false;

    const fakeRes = {
      status(code: number) {
        capturedStatus = code;
        return this;
      },
      json(payload: unknown) {
        capturedJson = payload;
        return this;
      },
    } as any;

    requireAuthenticatedUser(fakeReq, fakeRes, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(capturedStatus, 403);
    assert.equal(capturedJson?.error?.code, 'CSRF_ORIGIN_MISMATCH');

    // Verify isSecureRequest ignores multi-hop X-Forwarded-Proto when untrusted, and honors it when trust proxy is enabled
    const untrustedMultiHopReq = {
      secure: false,
      headers: {
        'x-forwarded-proto': 'https, http',
      },
    } as unknown as Request;
    assert.equal(isSecureRequest(untrustedMultiHopReq), false);

    const trustedMultiHopReq = {
      secure: false,
      headers: {
        'x-forwarded-proto': 'https, http',
      },
      app: {
        get: (key: string) => (key === 'trust proxy' ? 1 : undefined),
      },
    } as unknown as Request;
    assert.equal(isSecureRequest(trustedMultiHopReq), true);
  });

  it('boots cleanly via direct "node server.ts" execution on Node 22 in hosted preview mode and serves JSON auth endpoints', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const freePort = await new Promise<number>((resolve, reject) => {
      const probe = net.createServer();
      probe.listen(0, '127.0.0.1', () => {
        const addr = probe.address();
        const found = addr && typeof addr === 'object' ? addr.port : 0;
        probe.close((err) => (err ? reject(err) : resolve(found)));
      });
      probe.on('error', reject);
    });
    assert.ok(freePort > 0);

    const child = spawn(process.execPath, ['server.ts'], {
      cwd: repoRoot,
      env: {
        ...process.env,
        PORT: String(freePort),
        NODE_ENV: 'production',
        APPLET_ID: 'preview-applet-0050',
        APP_ENV: '',
        DATABASE_URL: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stderrLog = '';
    child.stderr.on('data', (chunk) => {
      stderrLog += String(chunk);
    });

    try {
      // Wait for GET /api/ready -> 200 JSON
      let readyOk = false;
      for (let i = 0; i < 40; i += 1) {
        if (child.exitCode !== null) {
          assert.fail(
            `node server.ts exited prematurely with code ${child.exitCode}: ${stderrLog}`
          );
        }
        try {
          const readyRes = await rawHttpRequest(freePort, {
            method: 'GET',
            path: '/api/ready',
          });
          if (readyRes.status === 200) {
            readyOk = true;
            break;
          }
        } catch {
          // Server still starting up
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.equal(readyOk, true, `Expected node server.ts to listen on ${freePort} (${stderrLog})`);

      // Unknown login returns 401 JSON (never SPA fallback HTML)
      const unknownLogin = await rawHttpRequest(freePort, {
        method: 'POST',
        path: '/api/auth/login',
        headers: {
          Host: `localhost:${freePort}`,
          'X-Forwarded-Host': 'ais-pre-vajra-preview.example.run.app',
          Origin: 'https://ais-pre-vajra-preview.example.run.app',
        },
        body: {
          email: 'missing.preview@vajra.test',
          password: 'ValidLengthPassword!1',
        },
      });
      assert.equal(unknownLogin.status, 401);
      assert.match(String(unknownLogin.headers['content-type'] ?? ''), /application\/json/i);
      assert.equal(unknownLogin.body?.error?.code, 'INVALID_CREDENTIALS');

      // Register + Login round-trip returns 201 / 200 JSON + __Host-vajra_session; Partitioned
      const regRes = await rawHttpRequest(freePort, {
        method: 'POST',
        path: '/api/auth/register',
        headers: {
          Host: `localhost:${freePort}`,
          'X-Forwarded-Host': 'ais-pre-vajra-preview.example.run.app',
          Origin: 'https://ais-pre-vajra-preview.example.run.app',
        },
        body: {
          email: 'node.direct.0050@vajra.test',
          displayName: 'Direct Node Runner',
          password: 'DirectNode-Password!22',
        },
      });
      assert.equal(regRes.status, 201);
      assert.equal(regRes.body?.user?.email, 'node.direct.0050@vajra.test');

      const loginRes = await rawHttpRequest(freePort, {
        method: 'POST',
        path: '/api/auth/login',
        headers: {
          Host: `localhost:${freePort}`,
          'X-Forwarded-Host': 'ais-pre-vajra-preview.example.run.app',
          Origin: 'https://ais-pre-vajra-preview.example.run.app',
        },
        body: {
          email: 'node.direct.0050@vajra.test',
          password: 'DirectNode-Password!22',
        },
      });
      assert.equal(loginRes.status, 200);
      assert.equal(loginRes.body?.authenticated, true);
      assert.equal(loginRes.body?.user?.email, 'node.direct.0050@vajra.test');
    } finally {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        await new Promise<void>((resolve) => {
          child.once('exit', () => resolve());
          setTimeout(() => {
            if (child.exitCode === null) child.kill('SIGKILL');
            resolve();
          }, 3000).unref();
        });
      }
    }
  });

  it('preserves fail-closed production refusal when NODE_ENV=production outside preview sandbox without DATABASE_URL', async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const child = spawn(process.execPath, ['server.ts'], {
      cwd: repoRoot,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        APPLET_ID: '',
        APP_ENV: '',
        DATABASE_URL: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stderrLog = '';
    child.stderr.on('data', (chunk) => {
      stderrLog += String(chunk);
    });

    const exitCode = await new Promise<number | null>((resolve) => {
      child.once('exit', (code) => resolve(code));
    });
    assert.notEqual(exitCode, 0, 'Production without DATABASE_URL must fail closed');
    assert.match(stderrLog, /Failed to start server/i);
  });
});
