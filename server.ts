/**
 * VAJRA Full-Stack Server Entry Point
 * Prompt 0003 / 0013: PostgreSQL via Prisma in production (fail closed);
 * in-memory repository only for local development / tests when DB is unset.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { createServer as createViteServer } from 'vite';
import { register as registerTsxEsm } from 'tsx/esm/api';
import type { IdentityRepository } from './src/server/db/repository.ts';

const alreadyLoadedByTsx = process.execArgv.some((arg) => arg.includes('tsx'));
if (!alreadyLoadedByTsx) {
  registerTsxEsm();
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function isProductionEnv(): boolean {
  const nodeEnv = process.env.NODE_ENV?.trim().toLowerCase();
  const appEnv = process.env.APP_ENV?.trim().toLowerCase();
  if (appEnv === 'production') {
    return true;
  }
  if (appEnv === 'development' || Boolean(process.env.APPLET_ID)) {
    return false;
  }
  return nodeEnv === 'production';
}

function isPlaceholderDatabaseUrl(dbUrl: string): boolean {
  const u = dbUrl.trim().toLowerCase();
  if (!u) return true;
  return (
    u.includes('username:password@') ||
    u.includes('user:password@') ||
    u.includes('localhost:5432/vajra_db') ||
    u.includes('example.com') ||
    u.includes('changeme')
  );
}

function resolveCliPortOverride(): number | null {
  const idx = process.argv.indexOf('--port');
  if (idx !== -1 && idx + 1 < process.argv.length) {
    const parsed = Number.parseInt(process.argv[idx + 1], 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
      return parsed;
    }
  }
  return null;
}

async function resolveIdentityRepository(): Promise<{
  repository: IdentityRepository;
  prisma: PrismaClient | null;
}> {
  const { PrismaIdentityRepository, InMemoryIdentityRepository } = await import(
    './src/server/db/repository.ts'
  );
  const dbUrl = process.env.DATABASE_URL?.trim() ?? '';
  const production = isProductionEnv();
  const looksPostgres =
    dbUrl.startsWith('postgresql://') || dbUrl.startsWith('postgres://');
  const placeholder = isPlaceholderDatabaseUrl(dbUrl);

  if (production) {
    if (!looksPostgres || placeholder) {
      throw new Error(
        '[VAJRA] Production requires a non-placeholder DATABASE_URL (PostgreSQL). In-memory fallback is disabled.'
      );
    }
    const prisma = new PrismaClient();
    try {
      await prisma.$connect();
    } catch {
      throw new Error(
        '[VAJRA] PostgreSQL is unreachable at startup. Production refuses to start without a healthy database.'
      );
    }
    return { repository: new PrismaIdentityRepository(prisma), prisma };
  }

  // Development / test: prefer PostgreSQL when configured; otherwise in-memory.
  if (looksPostgres && !placeholder) {
    try {
      const prisma = new PrismaClient();
      await prisma.$connect();
      return { repository: new PrismaIdentityRepository(prisma), prisma };
    } catch {
      console.warn(
        '[VAJRA] PostgreSQL connection unreachable in non-production; using in-memory repository.'
      );
      return { repository: new InMemoryIdentityRepository(), prisma: null };
    }
  }

  return { repository: new InMemoryIdentityRepository(), prisma: null };
}

async function startServer(): Promise<void> {
  const [{ createVajraApiApp }, { assertProductionConfigOrThrow, validateRuntimeConfig }] =
    await Promise.all([
      import('./src/server/app.ts'),
      import('./packages/config/src/index.ts'),
    ]);

  const production = isProductionEnv();
  if (production) {
    assertProductionConfigOrThrow(process.env);
  }

  const { config, valid, errors, warnings } = validateRuntimeConfig(process.env);
  if (production && !valid) {
    throw new Error(`[VAJRA] Production configuration invalid: ${errors.join(' ')}`);
  }
  for (const warning of warnings) {
    console.warn(`[VAJRA] Configuration warning: ${warning}`);
  }

  const distPath = path.join(__dirname, 'dist');
  const distIndex = path.join(distPath, 'index.html');
  if (production && !fs.existsSync(distIndex)) {
    throw new Error(
      '[VAJRA] Missing compiled web bundle (dist/index.html). Run `npm run build` before starting in production mode.'
    );
  }

  const { repository, prisma } = await resolveIdentityRepository();
  const app = createVajraApiApp({
    repository,
    totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY,
  });

  if (config.trustProxy) {
    app.set('trust proxy', 1);
  }

  const cliPort = resolveCliPortOverride();
  const envPort = process.env.PORT ? Number(process.env.PORT) : null;
  const PORT =
    cliPort ??
    (envPort && Number.isInteger(envPort) && envPort > 0 && envPort <= 65535
      ? envPort
      : 3000);

  const serveCompiledDist =
    (production || config.nodeEnv === 'production') && fs.existsSync(distIndex);

  // Production / built preview: serve Vite build; never let SPA fallback capture /api/*
  if (serveCompiledDist) {
    app.use(express.static(distPath, { index: false, maxAge: '1h' }));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        next();
        return;
      }
      res.sendFile(distIndex, (err) => {
        if (err) next(err);
      });
    });
  } else {
    // Development: Vite middleware mode (HMR disabled for agent stability)
    let viteMiddleware: express.RequestHandler | null = null;
    app.use((req, res, next) => {
      if (viteMiddleware) {
        viteMiddleware(req, res, next);
      } else {
        next();
      }
    });
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: false,
        watch: null,
        allowedHosts: true,
      },
      appType: 'spa',
    });
    viteMiddleware = vite.middlewares;
  }

  const server = http.createServer(app);

  const shutdown = async (signal: string) => {
    console.log(`[VAJRA] Received ${signal}; shutting down gracefully…`);
    server.close(async () => {
      try {
        if (prisma) {
          await prisma.$disconnect();
        }
      } catch {
        // ignore disconnect errors during shutdown
      }
      console.log('[VAJRA] Shutdown complete.');
      process.exit(0);
    });
    // Force exit if connections hang
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await new Promise<void>((resolve, reject) => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(
        `[VAJRA] Server listening on http://0.0.0.0:${PORT} (env=${config.nodeEnv}, identity=${repository.backendType})`
      );
      resolve();
    });
    server.on('error', reject);
  });
}

startServer().catch((err) => {
  const message = err instanceof Error ? err.message : 'Unknown error';
  // Never log full env or connection strings
  console.error('[VAJRA] Failed to start server:', message);
  process.exit(1);
});
