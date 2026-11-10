/**
 * VAJRA Backend API Express App Factory
 * Prompt 0003 / 0013 — Health + readiness, identity, auth, devices, notifications,
 * security headers, and fail-closed error handling.
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import { HealthResponse } from '../../packages/shared-types/src/index.ts';
import {
  IdentityRepository,
  InMemoryIdentityRepository,
} from './db/repository.ts';
import { createSessionResolutionMiddleware } from './auth/middleware.ts';
import { createAuthRouter } from './auth/routes.ts';
import { createDeviceRouter } from './devices/routes.ts';
import { createNotificationAndActivityRouter } from './notifications/routes.ts';

export interface CreateVajraApiOptions {
  repository?: IdentityRepository;
  totpEncryptionKey?: string;
  frameAncestors?: string;
  env?: Record<string, string | undefined>;
}

const TRUSTED_HTTPS_ANCESTOR_PATTERN =
  /^https:\/\/(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+|:\*)?$/i;
const TRUSTED_DEV_LOOPBACK_ANCESTOR_PATTERN =
  /^http:\/\/(localhost|127\.0\.0\.1)(:\d+|:\*)?$/i;

export interface ResolvedCspHeaders {
  readonly contentSecurityPolicy: string;
  readonly frameAncestors: string;
  readonly xFrameOptions: 'DENY' | 'SAMEORIGIN' | null;
  readonly strictTransportSecurity: string | null;
}

/**
 * Resolves Content-Security-Policy and framing headers with fail-safe defaults:
 * - Never emits `frame-ancestors *` or `script-src 'unsafe-eval'`.
 * - Standalone production (`APP_ENV=production` or `NODE_ENV=production` without `APPLET_ID`):
 *   - `script-src 'self'` (no `'unsafe-eval'`, no `'unsafe-inline'`).
 *   - Fails closed to `frame-ancestors 'none'` + `X-Frame-Options: DENY` unless `CSP_FRAME_ANCESTORS`
 *     specifies `'self'` or explicit `https://` origin(s) (wildcards `*` and `http://` are rejected).
 * - Hosted AI Studio preview (`APPLET_ID` present when `APP_ENV !== 'production'`):
 *   - Explicitly allows `'self' https://aistudio.google.com https://*.google.com` plus any validated
 *     `CSP_FRAME_ANCESTORS` origins so hosted iframe sign-in works without wildcard framing.
 * - Local development/test:
 *   - Defaults to `frame-ancestors 'self'` + `X-Frame-Options: SAMEORIGIN` unless explicit
 *     trusted origins are supplied via `CSP_FRAME_ANCESTORS` or `options.frameAncestors`.
 */
export function resolveSecurityResponseHeaders(options?: {
  env?: Record<string, string | undefined>;
  frameAncestors?: string;
}): ResolvedCspHeaders {
  const env = options?.env ?? process.env;
  const isHostedPreview = Boolean(env.APPLET_ID?.trim()) && env.APP_ENV !== 'production';
  const isStrictProduction =
    !isHostedPreview && (env.APP_ENV === 'production' || env.NODE_ENV === 'production');

  const rawConfigured = (options?.frameAncestors ?? env.CSP_FRAME_ANCESTORS ?? '').trim();
  let frameAncestors = isStrictProduction ? "'none'" : "'self'";
  let xFrameOptions: 'DENY' | 'SAMEORIGIN' | null = isStrictProduction ? 'DENY' : 'SAMEORIGIN';

  if (isHostedPreview) {
    const previewAllowed = ["'self'", 'https://aistudio.google.com', 'https://*.google.com'];
    if (rawConfigured && rawConfigured !== "'none'") {
      for (const token of rawConfigured.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean)) {
        if (
          TRUSTED_HTTPS_ANCESTOR_PATTERN.test(token) ||
          TRUSTED_DEV_LOOPBACK_ANCESTOR_PATTERN.test(token)
        ) {
          if (!previewAllowed.includes(token)) previewAllowed.push(token);
        }
      }
    }
    if (rawConfigured === "'none'") {
      frameAncestors = "'none'";
      xFrameOptions = 'DENY';
    } else {
      frameAncestors = previewAllowed.join(' ');
      xFrameOptions = null;
    }
  } else if (rawConfigured) {
    const tokens = rawConfigured
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (tokens.length === 1 && tokens[0] === "'none'") {
      frameAncestors = "'none'";
      xFrameOptions = 'DENY';
    } else if (!tokens.includes("'none'")) {
      const validOrigins: string[] = [];
      for (const token of tokens) {
        if (token === "'self'") {
          if (!validOrigins.includes("'self'")) validOrigins.push("'self'");
        } else if (TRUSTED_HTTPS_ANCESTOR_PATTERN.test(token)) {
          if (!validOrigins.includes(token)) validOrigins.push(token);
        } else if (!isStrictProduction && TRUSTED_DEV_LOOPBACK_ANCESTOR_PATTERN.test(token)) {
          if (!validOrigins.includes(token)) validOrigins.push(token);
        }
      }

      if (validOrigins.length > 0) {
        if (!validOrigins.includes("'self'")) {
          validOrigins.unshift("'self'");
        }
        frameAncestors = validOrigins.join(' ');
        xFrameOptions = validOrigins.length === 1 && validOrigins[0] === "'self'" ? 'SAMEORIGIN' : null;
      } else {
        // Untrusted or malformed input fails closed
        frameAncestors = isStrictProduction ? "'none'" : "'self'";
        xFrameOptions = isStrictProduction ? 'DENY' : 'SAMEORIGIN';
      }
    }
  }

  const cloudinary = 'https://res.cloudinary.com';
  const scriptSrc = isStrictProduction ? "script-src 'self'" : "script-src 'self' 'unsafe-inline'";
  const connectSrc = isStrictProduction
    ? "connect-src 'self' https: wss:"
    : "connect-src 'self' ws: wss: https:";

  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    `frame-ancestors ${frameAncestors}`,
    "form-action 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    `img-src 'self' data: blob: https: ${cloudinary}`,
    `media-src 'self' https: ${cloudinary}`,
    "font-src 'self' data: https://fonts.gstatic.com",
    connectSrc,
    "worker-src 'self' blob:",
  ];

  return {
    contentSecurityPolicy: directives.join('; '),
    frameAncestors,
    xFrameOptions,
    strictTransportSecurity:
      env.NODE_ENV === 'production' || env.APP_ENV === 'production'
        ? 'max-age=31536000; includeSubDomains'
        : null,
  };
}

export function buildContentSecurityPolicy(options?: {
  env?: Record<string, string | undefined>;
  frameAncestors?: string;
}): string {
  return resolveSecurityResponseHeaders(options).contentSecurityPolicy;
}

export function createVajraApiApp(options?: CreateVajraApiOptions): Express {
  const app = express();
  const repository = options?.repository ?? new InMemoryIdentityRepository();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  // Global security headers (HTML + API)
  app.use((_req: Request, res: Response, next: NextFunction) => {
    const resolvedHeaders = resolveSecurityResponseHeaders({
      env: options?.env,
      frameAncestors: options?.frameAncestors,
    });
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', resolvedHeaders.contentSecurityPolicy);
    if (resolvedHeaders.xFrameOptions) {
      res.setHeader('X-Frame-Options', resolvedHeaders.xFrameOptions);
    }
    if (resolvedHeaders.strictTransportSecurity) {
      // Safe when TLS terminates at App Service / Front Door with trust proxy enabled
      res.setHeader('Strict-Transport-Security', resolvedHeaders.strictTransportSecurity);
    }
    next();
  });

  // Sensitive API responses must not be cached by shared caches
  app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    next();
  });

  /**
   * GET /api/health — Liveness
   * Process is up; does not probe PostgreSQL.
   */
  app.get('/api/health', (_req: Request, res: Response<HealthResponse>) => {
    res.status(200).json({
      status: 'ok',
      service: 'vajra-api',
    });
  });

  /**
   * GET /api/ready — Readiness
   * Probes identity backend with a bounded timeout. Never returns connection strings.
   */
  app.get('/api/ready', async (_req: Request, res: Response) => {
    try {
      const health = await repository.checkDatabaseHealth(2000);
      if (!health.ok) {
        res.status(503).json({
          status: 'not_ready',
          service: 'vajra-api',
          checks: {
            identityStore: {
              ok: false,
              backend: health.backend,
              errorCode: health.errorCode ?? 'DATABASE_UNAVAILABLE',
            },
          },
        });
        return;
      }
      res.status(200).json({
        status: 'ready',
        service: 'vajra-api',
        checks: {
          identityStore: {
            ok: true,
            backend: health.backend,
            latencyMs: health.latencyMs,
          },
        },
      });
    } catch {
      res.status(503).json({
        status: 'not_ready',
        service: 'vajra-api',
        checks: {
          identityStore: {
            ok: false,
            errorCode: 'READINESS_PROBE_FAILED',
          },
        },
      });
    }
  });

  // Resolve session cookies on /api routes
  app.use('/api', createSessionResolutionMiddleware(repository));

  app.use(
    '/api',
    createAuthRouter({
      repository,
      totpEncryptionKey: options?.totpEncryptionKey,
    })
  );

  app.use(
    '/api',
    createDeviceRouter({
      repository,
    })
  );

  app.use(
    '/api',
    createNotificationAndActivityRouter({
      repository,
    })
  );

  app.use('/api', (_req: Request, res: Response) => {
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: 'API endpoint not found.',
      },
    });
  });

  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected server error occurred.',
      },
    });
  });

  return app;
}
