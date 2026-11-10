#!/usr/bin/env bash
# VAJRA — PostgreSQL Restore Helper with Explicit Destructive-Action Guard (Prompt 0048)
# Verifies backup SHA-256 integrity and requires explicit confirmation before restoring.

set -euo pipefail

ARCHIVE_PATH="${1:-}"
if [[ -z "$ARCHIVE_PATH" || ! -f "$ARCHIVE_PATH" ]]; then
  echo "Usage: VAJRA_CONFIRM_RESTORE=YES_OVERWRITE_TARGET_DB DATABASE_URL=... $0 <path-to-backup.dump>" >&2
  exit 1
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[VAJRA][ERROR] DATABASE_URL must be set in the environment." >&2
  exit 1
fi

if [[ "${VAJRA_CONFIRM_RESTORE:-}" != "YES_OVERWRITE_TARGET_DB" ]]; then
  echo "[VAJRA][BLOCKED] Refusing to overwrite target database without VAJRA_CONFIRM_RESTORE=YES_OVERWRITE_TARGET_DB." >&2
  exit 2
fi

if [[ "${NODE_ENV:-}" == "production" || "${APP_ENV:-}" == "production" ]]; then
  if [[ "${VAJRA_ALLOW_PRODUCTION_RESTORE:-}" != "YES_PRODUCTION_BREAK_GLASS" ]]; then
    echo "[VAJRA][BLOCKED] Refusing to restore while NODE_ENV/APP_ENV is production without VAJRA_ALLOW_PRODUCTION_RESTORE=YES_PRODUCTION_BREAK_GLASS." >&2
    exit 2
  fi
fi

CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
if [[ -f "$CHECKSUM_PATH" ]]; then
  echo "[VAJRA] Verifying backup SHA-256 digest..."
  sha256sum --check "$CHECKSUM_PATH"
fi

PG_URI="$(node -e '
  const raw = process.env.DATABASE_URL;
  const u = new URL(raw);
  for (const k of ["schema", "pgbouncer", "connection_limit", "pool_timeout"]) {
    u.searchParams.delete(k);
  }
  process.stdout.write(u.toString());
')"

echo "[VAJRA] Restoring ${ARCHIVE_PATH} into target database..."
pg_restore --clean --if-exists --single-transaction --no-owner --no-privileges --dbname="$PG_URI" "$ARCHIVE_PATH"
echo "[VAJRA] Restore completed. Verify schema state with 'npx prisma migrate status' and '/api/ready'."
