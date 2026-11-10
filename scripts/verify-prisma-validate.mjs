#!/usr/bin/env node
/**
 * VAJRA — Safe Prisma Schema Validation Runner (Prompt 0036)
 *
 * Runs `npx prisma validate` using the environment's DATABASE_URL if set,
 * or a non-secret syntax-only placeholder URL so schema validation never
 * requires live credentials or exposes secrets in logs.
 */

import { spawnSync } from 'node:child_process';

const env = {
  ...process.env,
  DATABASE_URL:
    process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0
      ? process.env.DATABASE_URL
      : 'postgresql://placeholder:placeholder@127.0.0.1:5432/vajra_validate_only?schema=public',
};

const result = spawnSync('npx', ['prisma', 'validate'], {
  stdio: 'inherit',
  env,
});

process.exit(result.status ?? 1);
