#!/usr/bin/env node
/**
 * VAJRA — Windows Agent Build & Protocol-Parity Verification Runner (Prompt 0036)
 *
 * Checks prerequisites for building `apps/windows-agent` (`net8.0-windows`)
 * and running `apps/windows-agent/tests/Vajra.ProtocolParity`:
 * 1. Host OS must be Windows (`process.platform === 'win32'`) for the Windows Worker Service target.
 * 2. `.NET 8 SDK` (`dotnet`) must be installed and available on PATH.
 *
 * Never simulates a Windows agent process or converts missing prerequisites into a pass.
 * Exits with code 2 (BLOCKED) when prerequisites are absent.
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';

const BLOCKED_EXIT_CODE = 2;

const isWindows = process.platform === 'win32';
const dotnetCheck = spawnSync(isWindows ? 'where' : 'which', ['dotnet'], {
  encoding: 'utf8',
});
const hasDotnet = dotnetCheck.status === 0 && Boolean(dotnetCheck.stdout.trim());

const missing = [];
if (!isWindows) {
  missing.push(`Windows 10 22H2+ / Windows 11 host required (current platform: ${process.platform} ${process.arch})`);
}
if (!hasDotnet) {
  missing.push('.NET 8 SDK (dotnet CLI) not found on PATH');
}

if (missing.length > 0) {
  console.error(`BLOCKED [test:windows-agent]: Missing prerequisite(s): ${missing.join('; ')}.`);
  console.error(
    'Real Windows agent build and protocol-parity tests were NOT RUN. See apps/windows-agent/README.md and docs/quality/verification-readiness-0036.md.'
  );
  process.exit(BLOCKED_EXIT_CODE);
}

const agentDir = path.resolve(process.cwd(), 'apps', 'windows-agent');

for (const args of [
  ['restore'],
  ['build', '-c', 'Release'],
  ['test', 'tests/Vajra.ProtocolParity', '-c', 'Release'],
]) {
  console.log(`[test:windows-agent] Running: dotnet ${args.join(' ')}`);
  const res = spawnSync('dotnet', args, {
    cwd: agentDir,
    stdio: 'inherit',
  });
  if (res.status !== 0) {
    process.exit(res.status ?? 1);
  }
}
