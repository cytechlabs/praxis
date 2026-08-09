#!/bin/bash
# PRA-179 Slice 4: fail-fast on pg_dump errors. Without ``set -euo
# pipefail`` an auth/connection failure leaves an empty .dump file
# on the backup_data volume while this script still exits 0 and
# prints "Backup completed: ...", masking the failure from the
# operator and the daily cron.
#
# PRA-263: publish backups atomically only after validation. pg_dump
# writes to a same-directory temp path that does NOT match ``*.dump``;
# the completed dump is validated with ``pg_restore --list`` and only
# then renamed into the final ``*.dump`` name that restore selection
# globs for. A failed, interrupted, or validation-failed dump is
# cleaned up and never leaves a final-looking ``.dump`` behind.
set -euo pipefail

# Database credentials. POSTGRES_PASSWORD is required and non-empty: compose
# passes the deployment's own credential through to this sidecar. Falling back
# to a script-defined password would authenticate against a database that was
# never provisioned with it, producing nightly auth failures instead of a clear
# configuration error.
DB_USER="${POSTGRES_USER:-postgres}"
DB_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required - the backup sidecar must receive the deployment database password}"
DB_NAME="${POSTGRES_DB:-praxis}"
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"

# Backup directory. Overridable via env (defaults to the production
# path) so the focused PRA-263 tests can point it at a scratch dir;
# it is unset in production, where the default applies.
BACKUP_DIR="${BACKUP_DIR:-/backups}"
DATE="$(date +%Y%m%d%H%M%S)"

# Final published name — the unchanged convention that restore
# selection (``ls -t /backups/*.dump``) globs for.
BACKUP_FILE="$BACKUP_DIR/$DB_NAME-$DATE.dump"

# PRA-263: in-progress dump path. Leading dot + ``.tmp.$$`` suffix so
# it lives in the SAME directory (rename is atomic on one filesystem)
# yet can never match ``*.dump`` and be selected for restore.
TMP_FILE="$BACKUP_DIR/.$DB_NAME-$DATE.dump.tmp.$$"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Remove the in-progress temp file on ANY exit before a successful
# publish — error, failed validation, or interrupt. The trap is
# cleared right after the atomic rename so it never deletes the
# published backup.
cleanup() {
    rm -f "$TMP_FILE"
}
trap cleanup EXIT
# Ensure the EXIT trap also fires on interrupt/termination so an
# interrupted dump leaves no staging artifact.
trap 'exit 130' INT
trap 'exit 143' TERM

# Export password to avoid password prompt
export PGPASSWORD="$DB_PASSWORD"

# Pre-create the temp file with restrictive (0600) permissions so the
# dump bytes are never briefly world-readable; pg_dump truncates this
# existing file in place, preserving the mode, and the final rename
# preserves it too.
( umask 077; : > "$TMP_FILE" )

# Perform the backup using the custom format, writing to the TEMP
# path. With ``set -e`` a non-zero exit from pg_dump propagates, the
# EXIT trap removes the partial temp file, and no final ``.dump`` is
# published.
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -F c -b -v -f "$TMP_FILE" "$DB_NAME"

# Unset password
unset PGPASSWORD

# Validate the completed dump is a readable custom-format archive
# BEFORE publishing. A truncated/corrupt dump fails here and is
# cleaned up by the trap, so restore never sees it.
pg_restore --list "$TMP_FILE" > /dev/null

# Flush dirty pages so the dump bytes are durable before the rename
# (coarse but always available in the sidecar).
sync

# Atomic same-directory rename to the final convention. After this the
# file is a complete, validated backup — clear the EXIT trap so cleanup
# does not remove it.
mv -f "$TMP_FILE" "$BACKUP_FILE"
trap - EXIT INT TERM

# Flush again so the directory entry for the renamed file is durable.
sync

# Retention policy: delete FINAL published backups older than 30 days.
# Scoped to ``*.dump`` only — in-progress temp files use a leading dot
# and a ``.tmp.$$`` suffix, so they never match this glob and are never
# treated as restorable backups.
find "$BACKUP_DIR" -type f -name "*.dump" -mtime +30 -exec rm {} \;

echo "Backup completed: $BACKUP_FILE"
