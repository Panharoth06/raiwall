package migration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/stretchr/testify/require"
)

func TestMigrator_SQLite(t *testing.T) {
	sqlite.RegisterDriver()

	db, err := sql.Open("control_sqlite", "file:migration_test.db?mode=memory")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// 1. Initial run: should apply all migrations (versions 1 and 2)
	err = Run(ctx, db, "sqlite")
	require.NoError(t, err)

	// Verify migrations were recorded
	applied, err := getAppliedVersions(ctx, db)
	require.NoError(t, err)
	require.True(t, applied[1])
	require.True(t, applied[2])

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
