#!/usr/bin/env bash
# VAJRA — PostgreSQL Logical Backup Helper (Prompt 0048)
# Produces a compressed custom-format pg_dump archive + SHA-256 digest without printing DATABASE_URL.

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[VAJRA][ERROR] DATABASE_URL must be set in the environment." >&2
  exit 1
fi

BACKUP_DIR="${1:-./backups}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_PATH="${BACKUP_DIR}/vajra-pg-${TIMESTAMP}.dump"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

# Strip Prisma-specific query parameters (schema, pgbouncer, connection_limit) while preserving all libpq TLS parameters
PG_URI="$(node -e '
  const raw = process.env.DATABASE_URL;
  const u = new URL(raw);
  for (const k of ["schema", "pgbouncer", "connection_limit", "pool_timeout"]) {
    u.searchParams.delete(k);
  }
  process.stdout.write(u.toString());
')"

echo "[VAJRA] Creating logical PostgreSQL backup at ${ARCHIVE_PATH}..."
pg_dump --format=custom --no-owner --no-privileges --dbname="$PG_URI" --file="$ARCHIVE_PATH"
chmod 600 "$ARCHIVE_PATH"

sha256sum "$ARCHIVE_PATH" > "$CHECKSUM_PATH"
echo "[VAJRA] Backup completed and checksum recorded at ${CHECKSUM_PATH}."
