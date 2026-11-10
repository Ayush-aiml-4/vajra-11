# VAJRA — Azure App Service Deployment Guide

**Status:** Configuration & runbook (Prompt 0013) — **not evidence of a completed Azure deployment**  
**Primary host:** Azure App Service (Linux, Node.js)  
**Database:** Azure Database for PostgreSQL Flexible Server  

---

## 1. Why App Service

VAJRA is a unified Express + Vite SPA process (`server.ts`):

- One HTTP process serves `/api/*` and production static assets from `dist/`.
- App Service maps well to `PORT`, health probes, app settings (secrets), and TLS termination.
- Container Apps is a valid alternative if the team standardizes on containers; this guide focuses on App Service to avoid dual competing configs.

---

## 2. Prerequisites

1. Azure subscription and resource group.
2. **Azure Database for PostgreSQL** Flexible Server (or equivalent) with:
   - Database name (e.g. `vajra`)
   - Firewall rule allowing App Service outbound IPs **or** private access / VNet integration
   - TLS required (`sslmode=require` in connection string)
3. Least-privilege PostgreSQL role for the app (CONNECT + DML on app schema; no SUPERUSER).
4. App Service plan (Linux) and Web App with Node.js 20+ runtime.
5. Local tools: Node.js, npm, Azure CLI (optional), `openssl` for secrets.

---

## 3. Build & start commands

| Setting | Value |
| :--- | :--- |
| Build | `npm install --legacy-peer-deps && npx prisma generate && npm run build` |
| Start | `npm run start:prod` (or `NODE_ENV=production APP_ENV=production npx tsx server.ts`) |
| Health probe (liveness) | `GET /api/health` |
| Health probe (readiness) | `GET /api/ready` |

Configure App Service **Startup Command** to the start command above if the default does not invoke `package.json` scripts.

---

## 4. Application settings (App Service Configuration)

Set as **application settings** (never commit values):

| Name | Required | Notes |
| :--- | :---: | :--- |
| `NODE_ENV` | Yes | `production` |
| `APP_ENV` | Yes | `production` |
| `PORT` | Auto | App Service injects `PORT`; do not hardcode |
| `DATABASE_URL` | Yes | Postgres URL with `sslmode=require`; non-placeholder |
| `SESSION_SECRET` | Yes | ≥32 chars, high entropy |
| `TOTP_ENCRYPTION_KEY` | Yes | ≥32 chars, distinct from session secret |
| `TRUST_PROXY` | Yes | `true` (TLS terminates at App Service) |
| `APP_PUBLIC_ORIGIN` | Recommended | `https://<app>.azurewebsites.net` or custom domain |
| `SESSION_TTL_SECONDS` | Optional | Default 900 |
| `REQUIRE_MFA` | Optional | Default true |

Production startup **fails closed** if `DATABASE_URL` is missing/placeholder or secrets are weak. In-memory identity is **not** used in production.

---

## 5. Database migrations

From a trusted CI job or admin workstation with network access to PostgreSQL:

```bash
export DATABASE_URL="postgresql://app_user:***@pghost:5432/vajra?schema=public&sslmode=require"
npx prisma generate
npx prisma migrate deploy
```

**Order:** forward-only `0003` → `0004` → `0005` → `0006` → `0007`.  
Do **not** run `migrate reset` or rewrite applied migrations.

Migration contents (source inspection):

| Migration | Objects |
| :--- | :--- |
| 0003 | Identity foundation tables |
| 0004 | Full product schema, FKs, CHECKs, indexes |
| 0005 | Views, audit immutability trigger, command result function |
| 0006 | `DeviceSession.stepUpActionScope` |
| 0007 | Analytics composite indexes |

---

## 6. HTTPS & cookies

- Enable HTTPS-only on the Web App.
- With `TRUST_PROXY=true`, Express trusts `X-Forwarded-Proto` so session cookies set `Secure` and `__Host-` names when appropriate.
- Custom domain: bind certificate in App Service; set `APP_PUBLIC_ORIGIN` to the canonical HTTPS origin.

---

## 7. Smoke test with dummy data

1. Open `https://<app>/api/health` → `{"status":"ok","service":"vajra-api"}`.
2. Open `https://<app>/api/ready` → `status: "ready"` and `identityStore.ok: true`.
3. Register a test user via the UI (dummy email/password).
4. Enable MFA with an authenticator app (optional for smoke).
5. Confirm Overview analytics loads empty-safe counts (`dataSource: PERSISTED`).

---

## 8. Rollback considerations

- **App:** Redeploy previous known-good build artifact / Git commit.
- **Schema:** Prefer forward fix migrations; avoid down-migrations in production without a tested plan.
- **Secrets:** Rotate `SESSION_SECRET` only with awareness that existing sessions invalidate.

---

## 9. What this document does **not** claim

- No Azure resources were created by the repository authors in this prompt.
- Migrations were not executed against a live Azure database in this phase.
- Blob Storage and device agents remain planned product surfaces unless separately implemented.

---

## 10. Prompt 0025 — Preflight status (2026-10-10)

| Check | Result |
| :--- | :--- |
| Baseline lint / unit / build | PASS (73 unit tests; Vite production build) |
| `npm audit` | 0 vulnerabilities (`deepmerge-ts@8.0.2` override retained) |
| `npx prisma validate` | PASS with local validation URL |
| Azure CLI (`az`) | **Not installed** in the verification environment |
| Azure login / subscription | **Not authenticated** — no subscription ID available |
| Resource creation | **Not performed** (no auth, no cost approval) |
| Live deployment URL | **None** |

### Cost note (order-of-magnitude, region-dependent)

| Resource | Typical student / free-tier notes |
| :--- | :--- |
| App Service B1 Linux | Often a few USD/month; Free F1 exists but limited |
| PostgreSQL Flexible Server Burstable | Dominant cost driver; stop/delete when idle |
| Bandwidth / logs | Usually small for academic smoke tests |

**Do not create billable resources without explicit approval.**

### Exact next commands (on an authenticated workstation)

```bash
# 1) Install Azure CLI and log in
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
az account show

# 2) Choose region + unique suffix; set cost-conscious SKUs
export RG=vajra-rg
export LOC=eastus
export APP=vajra-web-$RANDOM
export PG=vajra-pg-$RANDOM

# 3) Create resources only after reviewing estimated cost in the portal
az group create -n $RG -l $LOC
# PostgreSQL Flexible Server + App Service — follow Azure student guidance;
# prefer free/shared tiers where eligible.

# 4) Set App Settings (values never committed)
# NODE_ENV=production APP_ENV=production TRUST_PROXY=true
# DATABASE_URL=...sslmode=require
# SESSION_SECRET=... TOTP_ENCRYPTION_KEY=...
# APP_PUBLIC_ORIGIN=https://$APP.azurewebsites.net

# 5) Migrate then deploy
export DATABASE_URL='postgresql://...'
npx prisma migrate deploy
# Deploy via zip / GitHub Actions / az webapp deploy

# 6) Smoke
curl -sS https://$APP.azurewebsites.net/api/health
curl -sS https://$APP.azurewebsites.net/api/ready
```


## 11. Stopping billable resources after academic testing

When the demonstration is finished:

1. Stop the App Service (or set to Free tier only if still needed).
2. Stop or **delete** the PostgreSQL Flexible Server if it is no longer required — it is usually the largest cost.
3. Delete the resource group only after confirming no other shared resources remain.
4. Rotate any secrets that were used in temporary environments.

Never leave a Burstable PostgreSQL server running unused.
