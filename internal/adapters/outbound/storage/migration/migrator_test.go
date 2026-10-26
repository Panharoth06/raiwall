package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestMigrator_SQLite(t *testing.T) {
	db, err := sql.Open("sqlite", "file:migration_test.db?mode=memory")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// 1. Initial run: should apply all migrations (versions 1, 2, and 3)
	err = Run(ctx, db, "sqlite")
	require.NoError(t, err)

	// Verify migrations were recorded
	applied, err := getAppliedVersions(ctx, db)
	require.NoError(t, err)
	require.True(t, applied[1])
	require.True(t, applied[2])
	require.True(t, applied[3])

	// Verify Phase 7 tables exist
	var count int
	err = db.QueryRowContext(ctx, "SELECT count(*) FROM raiwall_ip_groups").Scan(&count)
	require.NoError(t, err)
	err = db.QueryRowContext(ctx, "SELECT count(*) FROM raiwall_response_templates").Scan(&count)
	require.NoError(t, err)

	// 2. Second run: idempotency test (should skip applied)
	err = Run(ctx, db, "sqlite")
	require.NoError(t, err)
}

func TestNormalizeDriver(t *testing.T) {
	require.Equal(t, "postgres", NormalizeDriver("Postgres"))
	require.Equal(t, "postgres", NormalizeDriver("postgresql"))
	require.Equal(t, "postgres", NormalizeDriver("pgx"))
	require.Equal(t, "sqlite", NormalizeDriver("sqlite3"))
	require.Equal(t, "sqlite", NormalizeDriver("control_sqlite"))
	require.Equal(t, "clickhouse", NormalizeDriver("clickhouse"))
}
