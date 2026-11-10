#!/usr/bin/env bash
# VAJRA — Azure App Service Startup Script (Prompt 0048)
# Verifies built SPA assets, applies forward-only Prisma SQL migrations, and starts the hardened server.
# Never prints environment secrets or connection strings.

set -euo pipefail

APP_ROOT="${APP_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$APP_ROOT"

export NODE_ENV="production"
export APP_ENV="production"

if [[ ! -f "$APP_ROOT/dist/index.html" ]]; then
  echo "[VAJRA][FATAL] Production frontend build missing at dist/index.html. Run 'npm run build' during CI/CD packaging." >&2
  exit 1
fi

echo "[VAJRA] Applying forward-only Prisma migrations..."
npx prisma migrate deploy

echo "[VAJRA] Starting VAJRA production API & static console..."
exec node server.ts
