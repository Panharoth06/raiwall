package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestControlStoreDSNResolvesNamedStore(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Storage
		want string
	}{
		{
			name: "database_url shortcut",
			cfg:  config.Storage{DatabaseURL: "file:/data/raiwall.db"},
			want: "file:/data/raiwall.db",
		},
		{
			name: "named control store",
			cfg: config.Storage{
				Stores: map[string]config.Store{
					"control": {Driver: "sqlite", DSN: "file:/data/control.db"},
					"events":  {Driver: "postgres", DSN: "postgres://events"},
				},
				Control: "control",
			},
			want: "file:/data/control.db",
		},
		{
			name: "default store fallback",
			cfg: config.Storage{
				Stores: map[string]config.Store{"default": {Driver: "sqlite", DSN: "file:/data/default.db"}},
			},
			want: "file:/data/default.db",
		},
		{
			name: "nothing configured",
			cfg:  config.Storage{},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, controlStoreDSN(&config.File{Storage: tc.cfg}))
		})
	}
}

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
