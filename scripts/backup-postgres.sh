#!/usr/bin/env bash
# ==============================================================================
# Back up the Raiwall PostgreSQL control database.
# ==============================================================================
# Modes:
#   DATABASE_URL=postgres://... ./scripts/backup-postgres.sh [output.dump]
#   COMPOSE_FILE=docker-compose.prod.yml ./scripts/backup-postgres.sh [output.dump]
#
# The backup uses pg_dump -Fc and is verified with pg_restore --list when the
# client tools are available. RPO equals the schedule interval (run from cron or
# the Helm backup CronJob).
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/docker-compose.prod.yml}"
OUTPUT="${1:-${REPO_ROOT}/backups/raiwall-$(date -u +%Y%m%d-%H%M%S).dump}"
mkdir -p "$(dirname "$OUTPUT")"
if [[ -e "$OUTPUT" ]]; then
    echo "refusing to overwrite existing backup: $OUTPUT" >&2
    exit 1
fi

if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "would write $OUTPUT"
    exit 0
fi

# Never leave a partial or empty archive behind after a failed dump.
cleanup_partial() {
    if [[ -f "$OUTPUT" && ! -s "$OUTPUT" ]]; then
        rm -f "$OUTPUT"
    fi
}
trap cleanup_partial EXIT

if [[ -n "${DATABASE_URL:-}" ]]; then
    command -v pg_dump >/dev/null || { echo "pg_dump is required" >&2; exit 1; }
    pg_dump --format=custom --no-owner --file "$OUTPUT" "$DATABASE_URL"
elif command -v docker >/dev/null; then
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        pg_dump -U "${POSTGRES_USER:-raiwall}" --format=custom --no-owner \
        "${POSTGRES_DB:-raiwall}" > "$OUTPUT"
else
    echo "set DATABASE_URL or run where docker compose is available" >&2
    exit 1
fi

if [[ ! -s "$OUTPUT" ]]; then
    echo "backup is empty: $OUTPUT" >&2
    exit 1
fi
if command -v pg_restore >/dev/null; then
    pg_restore --list "$OUTPUT" >/dev/null
fi
echo "backup written to $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
