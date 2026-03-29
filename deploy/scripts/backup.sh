#!/bin/bash
# ============================================================
# Zovark Database Backup
# Dumps PostgreSQL to timestamped file, keeps last 7 backups
# ============================================================
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${DEPLOY_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/zovark_${TIMESTAMP}.sql.gz"
KEEP_DAYS=7

mkdir -p "$BACKUP_DIR"

cd "$DEPLOY_DIR"

echo "=== Zovark Backup ==="
echo "Output: $BACKUP_FILE"

# Dump and compress
docker compose -f docker-compose.production.yml exec -T postgres \
    pg_dump -U zovark -d zovark --clean --if-exists | gzip > "$BACKUP_FILE"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup complete: $SIZE"

# Cleanup old backups
DELETED=0
find "$BACKUP_DIR" -name "zovark_*.sql.gz" -mtime +${KEEP_DAYS} -type f | while read -r old; do
    rm -f "$old"
    DELETED=$((DELETED + 1))
done

TOTAL=$(find "$BACKUP_DIR" -name "zovark_*.sql.gz" -type f | wc -l)
echo "Backups retained: $TOTAL (keeping ${KEEP_DAYS} days)"
