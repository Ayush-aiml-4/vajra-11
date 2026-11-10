#!/usr/bin/env node
/**
 * VAJRA — Reproducible PostgreSQL Integration Test Runner (Prompt 0036)
 *
 * Enforces explicit test-database safety guards and prerequisite checks:
 * 1. Rejects execution if NODE_ENV=production or APP_ENV=production.
 * 2. Requires VAJRA_PG_INTEGRATION=1.
 * 3. Requires a non-placeholder PostgreSQL DATABASE_URL (or VAJRA_TEST_DATABASE_URL)
 *    whose database name explicitly contains "test" (e.g. `vajra_test`) and
 *    does not target known managed production hosts unless VAJRA_ALLOW_REMOTE_TEST_DB=1.
 * 4. Verifies TCP reachability to the configured PostgreSQL endpoint before running.
 * 5. Never logs credentials or full connection strings.
 * 6. Produces an explicit BLOCKED result (exit code 2) when prerequisites are missing.
 */

import { spawnSync } from 'node:child_process';
import net from 'node:net';

const BLOCKED_EXIT_CODE = 2;

function block(reason) {
  console.error(`BLOCKED [test:pg]: ${reason}`);
  process.exit(BLOCKED_EXIT_CODE);
}

const nodeEnv = (process.env.NODE_ENV ?? '').trim().toLowerCase();
const appEnv = (process.env.APP_ENV ?? '').trim().toLowerCase();
if (nodeEnv === 'production' || appEnv === 'production') {
  block('Refusing to run integration tests when NODE_ENV or APP_ENV is "production".');
}

if (process.env.VAJRA_PG_INTEGRATION !== '1') {
  block(
    'Missing prerequisite: VAJRA_PG_INTEGRATION=1 is not set. Set VAJRA_PG_INTEGRATION=1 and a disposable test DATABASE_URL.'
  );
}

const rawDbUrl = (
  process.env.VAJRA_TEST_DATABASE_URL ??
  process.env.DATABASE_URL ??
  ''
).trim();

if (!rawDbUrl) {
  block(
    'Missing prerequisite: DATABASE_URL (or VAJRA_TEST_DATABASE_URL) is not set. Provide a disposable test PostgreSQL URL.'
  );
}

const lowerUrl = rawDbUrl.toLowerCase();
if (
  lowerUrl.includes('username:password@') ||
  lowerUrl.includes('user:password@') ||
  lowerUrl.includes('replace-me') ||
  lowerUrl.includes('changeme') ||
  lowerUrl.includes('example.com') ||
  lowerUrl.includes('localhost:5432/vajra_db')
) {
  block(
    'Safety check failed: DATABASE_URL is a placeholder value. Configure a real disposable local PostgreSQL test database (e.g. database name "vajra_test").'
  );
}

let parsed;
try {
  parsed = new URL(rawDbUrl);
} catch {
  block('Safety check failed: DATABASE_URL is not a valid URL.');
}

if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
  block('Safety check failed: DATABASE_URL must use postgresql:// or postgres:// protocol.');
}

const dbName = parsed.pathname.replace(/^\//, '').trim();
if (!dbName || !dbName.toLowerCase().includes('test')) {
  block(
    `Safety check failed: Disposable test database name must contain "test" (found "${dbName || '<empty>'}"). Never point integration tests at a production or primary database.`
  );
}

const host = parsed.hostname.toLowerCase();
const isLocalHost =
  host === '127.0.0.1' || host === 'localhost' || host === '::1';
if (!isLocalHost && process.env.VAJRA_ALLOW_REMOTE_TEST_DB !== '1') {
  block(
    `Safety check failed: Non-loopback database host "${host}" rejected by default. Use 127.0.0.1/localhost for disposable test databases.`
  );
}

const port = parsed.port ? Number.parseInt(parsed.port, 10) : 5432;

function checkTcpReachable(targetHost, targetPort, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(targetPort, targetHost);
  });
}

const reachable = await checkTcpReachable(parsed.hostname, port, 2000);
if (!reachable) {
  block(
    `Missing prerequisite: PostgreSQL server is not reachable at ${parsed.hostname}:${port} (db="${dbName}"). Start a local disposable PostgreSQL instance before running npm run test:pg.`
  );
}

console.log(
  `[test:pg] Safety check passed (host=${parsed.hostname}:${port}, db=${dbName}). Applying migrations and running PostgreSQL integration suite...`
);

const childEnv = {
  ...process.env,
  NODE_ENV: 'test',
  APP_ENV: 'test',
  VAJRA_PG_INTEGRATION: '1',
  DATABASE_URL: rawDbUrl,
};

const migrateRes = spawnSync('npx', ['prisma', 'migrate', 'deploy'], {
  stdio: 'inherit',
  env: childEnv,
});
if (migrateRes.status !== 0) {
  console.error('[test:pg] prisma migrate deploy failed.');
  process.exit(migrateRes.status ?? 1);
}

const testRes = spawnSync(
  'npx',
  ['tsx', '--test', 'tests/postgres-integration.test.ts'],
  {
    stdio: 'inherit',
    env: childEnv,
  }
);

process.exit(testRes.status ?? 1);
