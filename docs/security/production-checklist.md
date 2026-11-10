# VAJRA — Production Security Checklist

**Status:** Prompt 0051 source-grounded operational security checklist  
Use before exposing any deployment beyond a private disposable test slot.

## Configuration (Deployment Operator Responsibility)

- [ ] `NODE_ENV=production` and `APP_ENV=production`
- [ ] Non-placeholder `DATABASE_URL` with TLS (`sslmode=require`) and `DATABASE_SSL_REQUIRED=true`
- [ ] Canonical `https://` `APP_PUBLIC_ORIGIN` with `REQUIRE_PUBLIC_ORIGIN=true`
- [ ] Distinct `SESSION_SECRET` and `TOTP_ENCRYPTION_KEY` (≥32 chars each, provisioned via Key Vault)
- [ ] `TRUST_PROXY=true` ONLY behind a verified TLS-terminating reverse proxy (e.g., Azure App Service frontend); leave `TRUST_PROXY=false` when directly exposed so client-supplied `X-Forwarded-*` headers are ignored
- [ ] `VAJRA_ENABLE_DEMO_ENDPOINTS=false`
- [ ] Leave `CSP_FRAME_ANCESTORS` unset (enforces `frame-ancestors 'none'` + `X-Frame-Options: DENY`), or set explicit `https://` trusted origin(s) if parent framing is intentionally required (wildcards `*` and `http://` origins are rejected in production config validation)
- [ ] HTTPS-only ingress; HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) emitted in production
- [ ] App settings / Key Vault (`infrastructure/azure/main.bicep`) — zero secrets in repository or logs

## Application Controls (Implemented & Regression-Tested in Code)

- [x] **Framing & CSP Hardening (`src/server/app.ts`, `packages/config/src/index.ts`):** `script-src 'self'` (zero `'unsafe-eval'`), `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, standalone production default `frame-ancestors 'none'` + `X-Frame-Options: DENY`, `X-Permitted-Cross-Domain-Policies: none`
- [x] **Trusted-Proxy Boundary (`src/server/auth/middleware.ts`, `src/server/auth/routes.ts`):** `X-Forwarded-Proto`, `X-Forwarded-Ssl`, `X-Forwarded-Host`, and `X-Forwarded-For` are ignored unless `trust proxy` is enabled or the peer socket + `Host` header belong to a verified local loopback proxy (prevents rate-limit IP spoofing and CSRF host spoofing)
- [x] **CSRF + Origin/Referer Validation:** Session-bound `X-CSRF-Token` timing-safe hash check + `Origin`/`Referer` enforcement against `APP_PUBLIC_ORIGIN` in production
- [x] **Session Security:** `HttpOnly` cookies (`__Host-vajra_session` with `Secure; Path=/; SameSite=None; Partitioned` over HTTPS; `vajra_session` with `SameSite=Lax` on plain HTTP localhost), idle + absolute expiry, automatic token rotation, active session listing & per-session revocation (`/api/auth/sessions`)
- [x] **MFA & Step-Up:** Argon2id password hashing, AES-256-GCM encrypted TOTP secrets, single-use hashed recovery codes, and 5-minute action-scoped one-time step-up grants (`/api/auth/step-up`)
- [x] **Plane-2 Device Authentication:** ECDSA P-256 `VAJRA-DEVICE-AUTH-V1` canonical payload signatures, ±120s clock-skew window, atomic nonce replay rejection (`409 NONCE_REPLAYED`), and route-to-header device ID binding
- [x] **Platform Command Capability Enforcement (`src/server/notifications/routes.ts`):** Server rejects unsupported commands (`REQUEST_LOCATION`, `DISPLAY_RECOVERY_MESSAGE`, and Windows `RING_DEVICE`) with `400 UNSUPPORTED_COMMAND_FOR_PLATFORM` before step-up consumption or DB queueing; queued commands never report completed without a signed Plane-2 device receipt; terminal command states are immutable
- [x] **Truthful Lost Mode & Revocation Cleanup:** `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` explicitly operate as server-side VAJRA account lifecycle transitions (`executionScope: 'SERVER_ACCOUNT_STATE'`, `physicalLockApplied: false`, `liveLocationTracking: false`) without fabricating `ONLINE` connectivity; device `revoke` and `decommission` cancel pending commands and allow fresh-key re-enrollment
- [x] **Tamper-Evident Audit Trail:** SHA-256 hash-chained `AuditLog` with `/api/audit/verify` verification and PostgreSQL append-only trigger (`trg_prevent_audit_log_mutation`)
- [x] **ThreatCheck SSRF & Export Safety:** Zero outbound network fetches during URL inspection, query/fragment secret redaction, private/loopback/metadata IP detection, and CSV formula-injection neutralization (`escapeCsvCellSafe`)
- [x] **Fail-Closed Startup:** Production startup refuses missing/placeholder `DATABASE_URL`, unencrypted DB URLs when `DATABASE_SSL_REQUIRED=true`, missing `APP_PUBLIC_ORIGIN`, or missing `dist/index.html`

## Database

- [ ] Least-privilege PostgreSQL application role
- [ ] Private network / firewall restricts DB access to App Service only
- [ ] `npx prisma migrate deploy` applied cleanly through `0007_analytics_indexes`
- [ ] Automated Azure Flexible Server PITR enabled + `infrastructure/scripts/backup-postgres.sh` checksum archive verified

## Operations

- [ ] Health probes configured (`GET /api/health` liveness + `GET /api/ready` readiness)
- [ ] Startup command verified (`./infrastructure/scripts/startup-app-service.sh` -> `prisma migrate deploy` + `node server.ts`)
- [ ] Log stream reviewed for absence of credentials, tokens, TOTP secrets, or full connection strings
- [ ] Rollback procedure tested on disposable DB (`infrastructure/scripts/restore-postgres.sh` requires explicit `VAJRA_CONFIRM_RESTORE=YES_OVERWRITE_TARGET_DB`)

## CSP Notes

- `style-src 'self' 'unsafe-inline'` is retained for runtime Tailwind/Motion style attributes.
- `media-src 'self' https://res.cloudinary.com` and `img-src 'self' data: blob: https://res.cloudinary.com` allow the login background media without opening script execution origins.

## Native & Cloud External Execution Gates

- Windows Worker Service (`apps/windows-agent`) and Android Companion (`apps/android`) are implemented in repository; native runner compilation and physical device field tests require dedicated Windows 10/11 (`.NET 8 SDK`) and JDK 17 + Android SDK 34 hosts.
- Azure infrastructure (`infrastructure/azure/main.bicep`) is validated via offline preflight (`./infrastructure/scripts/azure-preflight.sh`) and has not been deployed to live cloud resources.

