package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/stretchr/testify/require"
)

// assertRealSQLiteFile guards against regressing to an in-memory stand-in:
// a real database always starts with the SQLite file header and grows well
// beyond the 16-byte magic-only stub the old driver wrote.
func assertRealSQLiteFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(16), "database file should contain real pages")

	header := make([]byte, 16)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Read(header)
	require.NoError(t, err)
	require.Equal(t, "SQLite format 3\x00", string(header))
}

func TestTelemetryStore_PersistsAcrossReopen(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "telemetry.db")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	store, err := NewTelemetryStore(TelemetryConfig{DSN: dsn})
	require.NoError(t, err)
	require.NoError(t, store.SaveBatch(ctx, []*telemetry.ForensicEvent{{
		EventID:    "persist-1",
		Timestamp:  now,
		Host:       "app.example.com",
		Path:       "/login",
		Method:     "POST",
		ClientIP:   "203.0.113.7",
		Action:     "block",
		RuleID:     "SEMANTIC_SQLI",
		Severity:   "high",
		StatusCode: 403,
	}}))
	require.NoError(t, store.Close())

	assertRealSQLiteFile(t, dsn)

	reopened, err := NewTelemetryStore(TelemetryConfig{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	event, err := reopened.GetEventByID(ctx, "persist-1")
	require.NoError(t, err)
	require.NotNil(t, event, "event must survive a process-style reopen")
	require.Equal(t, "app.example.com", event.Host)
	require.Equal(t, "SEMANTIC_SQLI", event.RuleID)
	require.True(t, event.Timestamp.Equal(now), "timestamp round-trip: got %v want %v", event.Timestamp, now)

	stats, err := reopened.QueryAggregates(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.TotalRequests)
	require.EqualValues(t, 1, stats.TotalBlocked)
}

func TestControlStore_PersistsAcrossReopen(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "control.db")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	store, err := InitDB(dsn)
	require.NoError(t, err)
	require.NoError(t, store.CreateUser(ctx, userRecord("persist-user", "persist-user", now)))
	require.NoError(t, store.Close())

	assertRealSQLiteFile(t, dsn)

	reopened, err := InitDB(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	user, err := reopened.GetUserByUsername(ctx, "persist-user")
	require.NoError(t, err)
	require.Equal(t, "persist-user", user.ID)
	require.Equal(t, "persist-user", user.Username)
	require.Equal(t, "admin", user.Role)
}

func TestPrepareDSN_QuarantinesLegacyStub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	require.NoError(t, os.WriteFile(path, []byte(sqliteMagic), 0o600))

	require.NoError(t, PrepareDSN("file:"+path+"?_pragma=busy_timeout(5000)"))

	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "magic-only stub must be moved aside")
	backup, err := os.ReadFile(path + ".legacy-stub")
	require.NoError(t, err)
	require.Equal(t, sqliteMagic, string(backup))

	store, err := NewTelemetryStore(TelemetryConfig{DSN: path})
	require.NoError(t, err)
	require.NoError(t, store.Close())
	assertRealSQLiteFile(t, path)
}

func TestPrepareDSN_LeavesRealDatabaseAndMemoryAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.db")
	store, err := NewTelemetryStore(TelemetryConfig{DSN: path})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	before, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, PrepareDSN(path))
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, before.Size(), after.Size())
	require.NoFileExists(t, path+".legacy-stub")

	require.NoError(t, PrepareDSN(":memory:"))
	require.NoError(t, PrepareDSN("file:shared?mode=memory&cache=shared"))
}

func userRecord(id, username string, now time.Time) control.UserRecord {
	return control.UserRecord{
		ID:           id,
		Username:     username,
		PasswordHash: fmt.Sprintf("hash-%s", id),
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
