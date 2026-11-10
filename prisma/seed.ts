/**
 * VAJRA — Safe Development Database Seed (`npm run db:seed`)
 * Prompt 0003 Section 13 & 33
 *
 * Security Rules Enforced:
 * - Strictly development-only (refuses to run if NODE_ENV === "production" or APP_ENV === "production")
 * - NEVER contains a hardcoded password anywhere in source code
 * - Reads VAJRA_SEED_EMAIL, VAJRA_SEED_DISPLAY_NAME, and VAJRA_SEED_PASSWORD from environment variables
 * - Idempotent: if the user already exists, exits cleanly without creating duplicate accounts
 * - Never prints or logs the password value
 */

import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../packages/security/src/node.ts';
import { PrismaIdentityRepository } from '../src/server/db/repository.ts';
import {
  validateEmailInput,
  validateDisplayNameInput,
  validatePasswordInput,
} from '../src/server/auth/validation.ts';

async function runDevelopmentSeed(): Promise<void> {
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  const appEnv = process.env.APP_ENV ?? 'development';

  if (nodeEnv === 'production' || appEnv === 'production') {
    console.error('[VAJRA Seed] BLOCKED: Development seed cannot run in production.');
    process.exit(1);
  }

  const seedEmail = process.env.VAJRA_SEED_EMAIL;
  const seedDisplayName = process.env.VAJRA_SEED_DISPLAY_NAME ?? 'VAJRA Owner';
  const seedPassword = process.env.VAJRA_SEED_PASSWORD;

  if (!seedEmail || !seedPassword) {
    console.error(
      '[VAJRA Seed] Missing environment variables: Set VAJRA_SEED_EMAIL and VAJRA_SEED_PASSWORD in your local .env before running `npm run db:seed`.'
    );
    process.exit(1);
  }

  const emailCheck = validateEmailInput(seedEmail);
  if (!emailCheck.valid || !emailCheck.normalizedEmail) {
    console.error(`[VAJRA Seed] Invalid VAJRA_SEED_EMAIL: ${emailCheck.error}`);
    process.exit(1);
  }

  const nameCheck = validateDisplayNameInput(seedDisplayName);
  if (!nameCheck.valid || !nameCheck.sanitizedName) {
    console.error(`[VAJRA Seed] Invalid VAJRA_SEED_DISPLAY_NAME: ${nameCheck.error}`);
    process.exit(1);
  }

  const passwordCheck = validatePasswordInput(seedPassword);
  if (!passwordCheck.valid) {
    console.error(`[VAJRA Seed] Invalid VAJRA_SEED_PASSWORD: ${passwordCheck.error}`);
    process.exit(1);
  }

  const prisma = new PrismaClient();
  try {
    await prisma.$connect();
    const repo = new PrismaIdentityRepository(prisma);

    const existing = await repo.findUserByEmail(emailCheck.normalizedEmail);
    if (existing) {
      console.log(
        `[VAJRA Seed] Account for ${existing.email} already exists (idempotent skip).`
      );
      return;
    }

    const passwordHash = await hashPassword(seedPassword);
    const { user } = await repo.createUserWithCredential({
      email: emailCheck.normalizedEmail,
      displayName: nameCheck.sanitizedName,
      passwordHash,
    });

    await repo.appendAuditEvent({
      actorUserId: user.id,
      eventType: 'ACCOUNT_CREATED',
      metadata: {
        source: 'DEVELOPMENT_SEED',
        email: user.email,
      },
    });

    console.log(`[VAJRA Seed] Created development account for ${user.email} (${user.id}).`);
  } finally {
    await prisma.$disconnect();
  }
}

runDevelopmentSeed().catch((err) => {
  console.error(
    '[VAJRA Seed] Seed failed:',
    err instanceof Error ? err.message : 'Unknown error'
  );
  process.exit(1);
});
