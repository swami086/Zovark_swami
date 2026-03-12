#!/bin/sh
# ============================================================
# HYDRA Database Restore Script
# Downloads backup from MinIO and restores to PostgreSQL
# Usage: ./scripts/restore-db.sh [daily|weekly] [filename]
#   e.g. ./scripts/restore-db.sh daily hydra_daily_20260312_030000.sql.gz
#   e.g. ./scripts/restore-db.sh  # lists available backups
# ============================================================
set -eu

POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-hydra}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-hydra_dev_2026}"
POSTGRES_DB="${POSTGRES_DB:-hydra}"
MINIO_ALIAS="${MINIO_ALIAS:-hydra}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
MINIO_BUCKET="${MINIO_BUCKET:-hydra-backups}"
MINIO_ACCESS_KEY="${MINIO_ROOT_USER:-hydra}"
MINIO_SECRET_KEY="${MINIO_ROOT_PASSWORD:-hydra_dev_2026}"
RESTORE_DIR="${RESTORE_DIR:-/tmp/hydra-restore}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Configure MinIO client
mc alias set "${MINIO_ALIAS}" "${MINIO_ENDPOINT}" "${MINIO_ACCESS_KEY}" "${MINIO_SECRET_KEY}" 2>/dev/null || true

# If no arguments, list available backups
if [ $# -eq 0 ]; then
    echo "=== Available Daily Backups ==="
    mc ls "${MINIO_ALIAS}/${MINIO_BUCKET}/daily/" 2>/dev/null || echo "  (none)"
    echo ""
    echo "=== Available Weekly Backups ==="
    mc ls "${MINIO_ALIAS}/${MINIO_BUCKET}/weekly/" 2>/dev/null || echo "  (none)"
    echo ""
    echo "Usage: $0 <daily|weekly> <filename>"
    exit 0
fi

BACKUP_TYPE="${1:-daily}"
BACKUP_FILE="${2:-}"

if [ -z "${BACKUP_FILE}" ]; then
    log "ERROR: Please specify a backup filename"
    log "Run '$0' with no arguments to list available backups"
    exit 1
fi

# Validate backup type
case "${BACKUP_TYPE}" in
    daily|weekly) ;;
    *) log "ERROR: Backup type must be 'daily' or 'weekly'"; exit 1 ;;
esac

mkdir -p "${RESTORE_DIR}"

# ─── DOWNLOAD BACKUP ───────────────────────────────────
REMOTE_PATH="${MINIO_ALIAS}/${MINIO_BUCKET}/${BACKUP_TYPE}/${BACKUP_FILE}"
LOCAL_PATH="${RESTORE_DIR}/${BACKUP_FILE}"

log "Downloading backup from MinIO: ${REMOTE_PATH}"
mc cp "${REMOTE_PATH}" "${LOCAL_PATH}"

# ─── CONFIRM RESTORE ───────────────────────────────────
log "WARNING: This will DROP and recreate the '${POSTGRES_DB}' database."
printf "Are you sure you want to proceed? [y/N] "
read -r confirm
case "${confirm}" in
    y|Y|yes|YES) ;;
    *) log "Restore cancelled."; rm -f "${LOCAL_PATH}"; exit 0 ;;
esac

# ─── RESTORE DATABASE ──────────────────────────────────
export PGPASSWORD="${POSTGRES_PASSWORD}"

log "Terminating active connections to '${POSTGRES_DB}'..."
psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d postgres -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${POSTGRES_DB}' AND pid <> pg_backend_pid();" \
    2>/dev/null || true

log "Dropping and recreating database..."
psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d postgres -c \
    "DROP DATABASE IF EXISTS ${POSTGRES_DB};"
psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d postgres -c \
    "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"

log "Restoring from backup..."
gunzip -c "${LOCAL_PATH}" | psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" --quiet

# ─── VERIFY ─────────────────────────────────────────────
TABLE_COUNT=$(psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -c \
    "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" | tr -d ' ')

log "Restore complete. Tables in database: ${TABLE_COUNT}"

# Cleanup
rm -f "${LOCAL_PATH}"
log "Done."
