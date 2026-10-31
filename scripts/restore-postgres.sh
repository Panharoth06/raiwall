#!/usr/bin/env bash
# ==============================================================================
# Restore the Raiwall PostgreSQL control database (stop the world).
# ==============================================================================
#   CONFIRM_RESTORE=yes DATABASE_URL=postgres://... ./scripts/restore-postgres.sh backup.dump
#   CONFIRM_RESTORE=yes COMPOSE_FILE=docker-compose.prod.yml ./scripts/restore-postgres.sh backup.dump
#
# This DROPS and recreates control-plane tables. Raiwall is stopped first in
# Compose mode. Take a fresh backup before restoring.
# ==============================================================================
set -euo pipefail

INPUT="${1:-}"
if [[ -z "$INPUT" || ! -s "$INPUT" ]]; then
    echo "usage: CONFIRM_RESTORE=yes $0 <backup.dump>" >&2
    exit 1
fi
if [[ "${CONFIRM_RESTORE:-}" != "yes" ]]; then
    echo "refusing to restore without CONFIRM_RESTORE=yes" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/docker-compose.prod.yml}"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "would restore $INPUT"
    exit 0
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
    command -v pg_restore >/dev/null || { echo "pg_restore is required" >&2; exit 1; }
    pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" "$INPUT"
else
    docker compose -f "$COMPOSE_FILE" stop raiwall
    cat "$INPUT" | docker compose -f "$COMPOSE_FILE" exec -T postgres \
        pg_restore --clean --if-exists --no-owner \
        -U "${POSTGRES_USER:-raiwall}" -d "${POSTGRES_DB:-raiwall}"
    docker compose -f "$COMPOSE_FILE" start raiwall
fi
echo "restore complete; verify /status and /readyz before resuming traffic"
