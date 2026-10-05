#!/usr/bin/env bash
# Connector OS — hot SQLite backup to Cloudflare R2
#
# Safe to run while the server is live — uses SQLite .backup API
# which creates a consistent snapshot without locking writes.
#
# Prerequisites on server:
#   apt install sqlite3 awscli
#
# Required env vars (add to /etc/environment or cron job):
#   CF_ACCOUNT_ID       — Cloudflare account ID (from R2 dashboard)
#   CF_R2_BUCKET        — e.g. connector-backups
#   CF_ACCESS_KEY_ID    — R2 API token key ID
#   CF_SECRET_ACCESS_KEY— R2 API token secret
#
# Crontab (daily at 02:00):
#   0 2 * * * /opt/connector/scripts/backup-db.sh >> /var/log/connector-backup.log 2>&1
#
# Restore:
#   aws s3 cp s3://$CF_R2_BUCKET/YYYY/MM/DD/license-backup-*.tar.gz . \
#       --endpoint-url https://$CF_ACCOUNT_ID.r2.cloudflarestorage.com
#   tar xzf license-backup-*.tar.gz
#   # Stop server, replace license.db + keys/, start server

set -euo pipefail

DB="${CONNECTOR_LICENSE_DATA_DIR:-/mnt/connector-data}/license.db"
KEYS_DIR="${CONNECTOR_LICENSE_DATA_DIR:-/mnt/connector-data}/keys"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DB="/tmp/license-backup-${STAMP}.db"
ARCHIVE="/tmp/license-backup-${STAMP}.tar.gz"
DATE_PATH="$(date +%Y/%m/%d)"

# ── Sanity checks ────────────────────────────────────────────────────────────
if [[ ! -f "$DB" ]]; then
    echo "[backup] ERROR: DB not found at $DB" >&2
    exit 1
fi

: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID not set}"
: "${CF_R2_BUCKET:?CF_R2_BUCKET not set}"
: "${CF_ACCESS_KEY_ID:?CF_ACCESS_KEY_ID not set}"
: "${CF_SECRET_ACCESS_KEY:?CF_SECRET_ACCESS_KEY not set}"

# ── Hot backup (consistent snapshot, no downtime) ────────────────────────────
echo "[backup] Creating hot snapshot of $DB ..."
sqlite3 "$DB" ".backup '$BACKUP_DB'"
echo "[backup] Snapshot size: $(du -sh "$BACKUP_DB" | cut -f1)"

# ── Bundle with keys (Ed25519 signing keypair — irreplaceable) ───────────────
echo "[backup] Bundling keys from $KEYS_DIR ..."
tar czf "$ARCHIVE" -C "$(dirname "$BACKUP_DB")" "$(basename "$BACKUP_DB")" \
    -C "$(dirname "$KEYS_DIR")" "$(basename "$KEYS_DIR")"
rm "$BACKUP_DB"
echo "[backup] Archive: $ARCHIVE ($(du -sh "$ARCHIVE" | cut -f1))"

# ── Upload to R2 ─────────────────────────────────────────────────────────────
ENDPOINT="https://${CF_ACCOUNT_ID}.r2.cloudflarestorage.com"
S3_KEY="${DATE_PATH}/$(basename "$ARCHIVE")"

AWS_ACCESS_KEY_ID="$CF_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$CF_SECRET_ACCESS_KEY" \
aws s3 cp "$ARCHIVE" "s3://${CF_R2_BUCKET}/${S3_KEY}" \
    --endpoint-url "$ENDPOINT" \
    --storage-class STANDARD \
    --no-progress

echo "[backup] Uploaded to r2://${CF_R2_BUCKET}/${S3_KEY}"

# ── Cleanup ──────────────────────────────────────────────────────────────────
rm "$ARCHIVE"

# ── Keep only last 30 days on R2 (delete older objects) ─────────────────────
CUTOFF="$(date -d '30 days ago' +%Y/%m/%d 2>/dev/null || date -v-30d +%Y/%m/%d)"
echo "[backup] Pruning backups older than $CUTOFF ..."
AWS_ACCESS_KEY_ID="$CF_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$CF_SECRET_ACCESS_KEY" \
aws s3 ls "s3://${CF_R2_BUCKET}/" \
    --endpoint-url "$ENDPOINT" --recursive \
    | awk '{print $4}' \
    | grep "^20" \
    | while read -r key; do
        key_date="${key:0:10}"  # YYYY/MM/DD
        if [[ "$key_date" < "$CUTOFF" ]]; then
            AWS_ACCESS_KEY_ID="$CF_ACCESS_KEY_ID" \
            AWS_SECRET_ACCESS_KEY="$CF_SECRET_ACCESS_KEY" \
            aws s3 rm "s3://${CF_R2_BUCKET}/${key}" \
                --endpoint-url "$ENDPOINT" --quiet
            echo "[backup] Pruned: $key"
        fi
    done

echo "[backup] Done: $(date)"
