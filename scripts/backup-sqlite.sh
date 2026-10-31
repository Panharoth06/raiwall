#!/usr/bin/env bash
# ==============================================================================
# Back up the embedded SQLite control database.
# ==============================================================================
#   DB_PATH=/var/lib/raiwall/raiwall.db ./scripts/backup-sqlite.sh [output.db]
#
# Prefer `raiwall backup --config ... --output ...` when the binary is
# available (VACUUM INTO + integrity check). This script uses the sqlite3 CLI.
# ==============================================================================
set -euo pipefail

DB_PATH="${DB_PATH:-}"
OUTPUT="${1:-./raiwall-sqlite-$(date -u +%Y%m%d-%H%M%S).db}"
if [[ -z "$DB_PATH" || ! -f "$DB_PATH" ]]; then
    echo "set DB_PATH to the SQLite control database" >&2
    exit 1
fi
command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 1; }
if [[ -e "$OUTPUT" ]]; then
    echo "refusing to overwrite existing backup: $OUTPUT" >&2
    exit 1
fi
if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "would back up $DB_PATH to $OUTPUT"
    exit 0
fi

sqlite3 "$DB_PATH" ".backup '$OUTPUT'"
integrity="$(sqlite3 "$OUTPUT" 'PRAGMA integrity_check;')"
if [[ "$integrity" != "ok" ]]; then
    echo "backup integrity check failed: $integrity" >&2
    exit 1
fi
echo "backup written to $OUTPUT"
