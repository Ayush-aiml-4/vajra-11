# VAJRA Infrastructure (`infrastructure/`)

**Status:** IaC, local disposable DB container, and operational scripts `IMPLEMENTED` in repository; live Azure cloud provisioning `NOT DEPLOYED` (requires authenticated Azure subscription and explicit cost approval).

## Contents

| Path | Purpose | Status |
| :--- | :--- | :--- |
| `azure/main.bicep` | Azure App Service (Linux Node 22 LTS), Private VNet PostgreSQL Flexible Server 15, Key Vault RBAC + Managed Identity secret references, Log Analytics, Application Insights, and Azure Monitor metric alerts | `IMPLEMENTED` (Not Deployed) |
| `azure/main.bicepparam.example` | Placeholder-only Bicep parameter file reading secrets from deployment environment variables | `IMPLEMENTED` |
| `docker/docker-compose.postgres.yml` | Ephemeral loopback (`127.0.0.1:5432`) PostgreSQL 15 container for local development and `npm run test:pg` | `IMPLEMENTED` |
| `scripts/startup-app-service.sh` | Fail-closed App Service startup entrypoint (`dist/index.html` check + forward-only `prisma migrate deploy` + `server.ts`) | `IMPLEMENTED` |
| `scripts/backup-postgres.sh` | Credential-safe `pg_dump --format=custom` logical backup + SHA-256 checksum generator | `IMPLEMENTED` |
| `scripts/restore-postgres.sh` | SHA-256 verified `pg_restore` helper guarded by `VAJRA_CONFIRM_RESTORE=YES_OVERWRITE_TARGET_DB` | `IMPLEMENTED` |
| `scripts/azure-preflight.sh` | Offline/local deployment readiness check (templates, migrations `0003`–`0007`, Prisma validation, production build, optional `az bicep build`) | `IMPLEMENTED` |

## Security Rules

- Never commit live secrets, connection strings, certificates, or populated `.bicepparam` files to this directory.
- Do not provision billable Azure resources without explicit owner approval.
