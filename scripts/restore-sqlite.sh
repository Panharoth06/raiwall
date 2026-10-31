#!/usr/bin/env bash
# ==============================================================================
# Restore the embedded SQLite control database (stop the world).
# ==============================================================================
#   CONFIRM_RESTORE=yes DB_PATH=/var/lib/raiwall/raiwall.db ./scripts/restore-sqlite.sh backup.db
#
# Stop Raiwall first, keep a copy of the current database, and remove stale
# -wal/-shm files. Verify /status and /readyz after restarting.
# ==============================================================================
set -euo pipefail

INPUT="${1:-}"
DB_PATH="${DB_PATH:-}"
if [[ -z "$INPUT" || ! -s "$INPUT" ]]; then
    echo "usage: CONFIRM_RESTORE=yes DB_PATH=... $0 <backup.db>" >&2
    exit 1
fi
if [[ -z "$DB_PATH" ]]; then
    echo "set DB_PATH to the SQLite control database" >&2
    exit 1
fi
if [[ "${CONFIRM_RESTORE:-}" != "yes" ]]; then
    echo "refusing to restore without CONFIRM_RESTORE=yes" >&2
    exit 1
fi
if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "would restore $INPUT over $DB_PATH"
    exit 0
fi

if command -v pgrep >/dev/null && pgrep -f 'raiwall run' >/dev/null; then
    echo "stop Raiwall before restoring" >&2
    exit 1
fi

if [[ -f "$DB_PATH" ]]; then
    cp "$DB_PATH" "$DB_PATH.before-restore.$(date -u +%Y%m%d-%H%M%S)"
fi
rm -f "$DB_PATH-wal" "$DB_PATH-shm"
cp "$INPUT" "$DB_PATH"
echo "restore complete; start Raiwall and verify /readyz"
