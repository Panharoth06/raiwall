package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestBackupSQLiteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "source.db") + "?_pragma=busy_timeout(5000)"
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, store.CreateUser(context.Background(), control.UserRecord{
		ID: "u1", Username: "alice", PasswordHash: "hash", Role: "admin",
		IsActive: 1, CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, store.Close())

	output := filepath.Join(dir, "backup.db")
	require.NoError(t, backupSQLite(dsn, output))

	backup, err := sql.Open("sqlite", "file:"+output)
	require.NoError(t, err)
	defer backup.Close()
	var username string
	require.NoError(t, backup.QueryRow("SELECT username FROM raiwall_users WHERE id = 'u1'").Scan(&username))
	require.Equal(t, "alice", username)

	require.Error(t, backupSQLite(dsn, output), "an existing destination must not be overwritten")
	require.Error(t, backupSQLite("postgres://example/db", filepath.Join(dir, "pg.dump")))
}
