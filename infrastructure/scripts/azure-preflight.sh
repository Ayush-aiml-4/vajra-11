#!/usr/bin/env bash
# VAJRA — Local / Offline Cloud Deployment Preflight Validator (Prompt 0048)
# Validates repository artifacts, migrations, build bundle, and secret-free templates WITHOUT contacting Azure.

set -euo pipefail

APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$APP_ROOT"

echo "[VAJRA][Preflight 1/5] Checking environment templates and Bicep files..."
for required_file in \
  ".env.example" \
  ".env.test.example" \
  ".env.production.example" \
  "infrastructure/azure/main.bicep" \
  "infrastructure/azure/main.bicepparam.example" \
  "infrastructure/scripts/startup-app-service.sh" \
  "infrastructure/scripts/backup-postgres.sh" \
  "infrastructure/scripts/restore-postgres.sh"; do
  if [[ ! -f "$required_file" ]]; then
    echo "[VAJRA][FAIL] Missing required operational artifact: $required_file" >&2
    exit 1
  fi
done

echo "[VAJRA][Preflight 2/5] Checking forward-only Prisma migration chain (0003..0007)..."
for mig in 0003 0004 0005 0006 0007; do
  if ! compgen -G "prisma/migrations/${mig}_*/migration.sql" > /dev/null; then
    echo "[VAJRA][FAIL] Missing Prisma migration prefix ${mig}_* under prisma/migrations/" >&2
    exit 1
  fi
done

echo "[VAJRA][Preflight 3/5] Validating Prisma schema..."
npm run db:validate

echo "[VAJRA][Preflight 4/5] Verifying production frontend build output..."
if [[ ! -f "dist/index.html" ]]; then
  npm run build
fi

echo "[VAJRA][Preflight 5/5] Checking optional Azure Bicep CLI compiler..."
if command -v az >/dev/null 2>&1 && az bicep version >/dev/null 2>&1; then
  az bicep build --file infrastructure/azure/main.bicep --stdout >/dev/null
  echo "[VAJRA] Azure Bicep compilation: PASS"
else
  echo "[VAJRA] Azure CLI / Bicep compiler not installed locally — Bicep compilation skipped (live deployment not attempted)."
fi

echo "[VAJRA] Offline cloud readiness preflight: PASS (zero Azure resources contacted or created)."
