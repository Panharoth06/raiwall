#!/bin/sh
set -e

# Default environment variables
POSTGRES_DB="${POSTGRES_DB:-raiwall}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
PGDATA="${PGDATA:-/var/lib/postgresql/data}"

# Helper to execute commands as postgres user
run_as_postgres() {
    if command -v su-exec >/dev/null 2>&1; then
        su-exec postgres "$@"
    elif command -v gosu >/dev/null 2>&1; then
        gosu postgres "$@"
    else
        su -s /bin/sh postgres -c "$*"
    fi
}

# Ensure directories have proper permissions
mkdir -p "$PGDATA" /run/postgresql /var/log/raiwall /var/lib/raiwall
chown -R postgres:postgres "$PGDATA" /run/postgresql

# 1. Initialize PostgreSQL 18 cluster if not already initialized
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "[Entrypoint] Initializing PostgreSQL 18 database cluster in $PGDATA..."
    run_as_postgres initdb -D "$PGDATA" --auth=trust > /dev/null

    # Configure postgresql.conf to listen on all interfaces
    echo "listen_addresses = '*'" >> "$PGDATA/postgresql.conf"
    echo "host all all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
    echo "host all all ::/0 md5" >> "$PGDATA/pg_hba.conf"
    echo "local all all trust" >> "$PGDATA/pg_hba.conf"

    # Start temporary postgres to configure user and db
    run_as_postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start > /dev/null

    # Set password for user and create database if needed
    run_as_postgres psql -v ON_ERROR_STOP=1 --username "postgres" --no-password <<-EOSQL
        ALTER USER "$POSTGRES_USER" WITH ENCRYPTED PASSWORD '$POSTGRES_PASSWORD';
        SELECT 'CREATE DATABASE $POSTGRES_DB' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB')\gexec
EOSQL

    run_as_postgres pg_ctl -D "$PGDATA" -m fast -w stop > /dev/null
    echo "[Entrypoint] PostgreSQL 18 database initialization complete."
fi

# 2. Start PostgreSQL 18 service in background
echo "[Entrypoint] Starting PostgreSQL 18..."
run_as_postgres postgres -D "$PGDATA" &
PG_PID=$!

# Wait for PostgreSQL 18 to be ready
echo "[Entrypoint] Waiting for PostgreSQL 18 to be ready on port 5432..."
for i in $(seq 1 30); do
    if run_as_postgres pg_isready -h 127.0.0.1 -p 5432 > /dev/null 2>&1; then
        echo "[Entrypoint] PostgreSQL 18 is ready on port 5432."
        break
    fi
    sleep 1
done

# Trap SIGTERM and SIGINT to gracefully shut down both services
shutdown() {
    echo "[Entrypoint] Shutting down services..."
    kill -TERM "$RAIWALL_PID" 2>/dev/null || true
    run_as_postgres pg_ctl -D "$PGDATA" -m fast stop 2>/dev/null || true
    wait "$RAIWALL_PID" 2>/dev/null || true
    wait "$PG_PID" 2>/dev/null || true
    exit 0
}
trap shutdown SIGTERM SIGINT

# 3. Start Raiwall WAF (Backend + Web Console on :8080)
echo "[Entrypoint] Starting Raiwall WAF Gateway (Backend + Web Console on :8080)..."
# Point the canonical config at the embedded PostgreSQL instance. The YAML file
# stays deployment-agnostic; this environment layer supplies the DSN.
export RAIWALL_CONFIG="${RAIWALL_CONFIG:-/etc/raiwall/raiwall.yaml}"
export RAIWALL_DATABASE_URL="${RAIWALL_DATABASE_URL:-postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}?sslmode=disable}"
if [ "$#" -eq 0 ]; then
    /usr/local/bin/raiwall &
else
    /usr/local/bin/raiwall "$@" &
fi
RAIWALL_PID=$!

wait "$RAIWALL_PID"
