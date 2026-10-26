package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/stretchr/testify/require"
)

func TestAutoDetectDriver(t *testing.T) {
	require.Equal(t, "postgres", AutoDetectDriver("postgres://user:pass@localhost:5432/db"))
	require.Equal(t, "postgres", AutoDetectDriver("postgresql://user:pass@localhost:5432/db?sslmode=disable"))
	require.Equal(t, "postgres", AutoDetectDriver("host=localhost user=postgres dbname=raiwall"))
	require.Equal(t, "sqlite", AutoDetectDriver("file:raiwall.db"))
	require.Equal(t, "sqlite", AutoDetectDriver("my_test.db"))
	require.Equal(t, "sqlite", AutoDetectDriver(":memory:"))
}

func TestRegistry_SharedPoolSameStore(t *testing.T) {
	ctx := context.Background()

	reg, err := NewRegistry(StorageConfig{
		Stores: map[string]StoreConfig{
			"shared_store": {
				Driver: "sqlite",
				DSN:    "file:shared_pool_test.db?mode=memory",
			},
		},
		Control:   "shared_store",
		Telemetry: "shared_store",
	})
	require.NoError(t, err)
	defer reg.Close()

	cs, err := reg.ControlStore(ctx)
	require.NoError(t, err)
	require.NotNil(t, cs)

	ts, err := reg.TelemetryStore(ctx)
	require.NoError(t, err)
	require.NotNil(t, ts)

	// Verify shared connection pool is reused
	require.Len(t, reg.pools, 1)
	require.NotNil(t, reg.pools["shared_store"])

	// Verify ControlStore operations work
	err = cs.CreateApp(ctx, control.SiteApp{
		ID:        "app-reg",
		Name:      "Registry App",
		Hostnames: `["app.example.com"]`,
		Mode:      "defense",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	app, err := cs.GetApp(ctx, "app-reg")
	require.NoError(t, err)
	require.Equal(t, "Registry App", app.Name)
}

func TestRegistry_SQLitePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := StorageConfig{
		Stores: map[string]StoreConfig{
			"ctrl": {
				Driver: "sqlite",
				DSN:    "file:" + filepath.Join(dir, "control.db") + "?_pragma=busy_timeout(5000)",
			},
			"tele": {
				Driver: "sqlite",
				DSN:    "file:" + filepath.Join(dir, "telemetry.db") + "?_pragma=busy_timeout(5000)",
			},
		},
		Control:   "ctrl",
		Telemetry: "tele",
	}
	now := time.Now().UTC().Truncate(time.Second)

	reg, err := NewRegistry(cfg)
	require.NoError(t, err)
	cs, err := reg.ControlStore(ctx)
	require.NoError(t, err)
	require.NoError(t, cs.CreateUser(ctx, control.UserRecord{
		ID: "registry-user", Username: "registry-user", PasswordHash: "hash",
		Role: "admin", IsActive: 1, CreatedAt: now, UpdatedAt: now,
	}))
	ts, err := reg.TelemetryStore(ctx)
	require.NoError(t, err)
	require.NoError(t, ts.SaveBatch(ctx, []*telemetry.ForensicEvent{{
		EventID: "registry-event", Timestamp: now, Host: "app.example.com",
		ClientIP: "203.0.113.9", Action: "block", RuleID: "SEMANTIC_SQLI", StatusCode: 403,
	}}))
	require.NoError(t, reg.Close())

	reopened, err := NewRegistry(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	user, err := reopened.ControlStore(ctx)
	require.NoError(t, err)
	record, err := user.GetUserByUsername(ctx, "registry-user")
	require.NoError(t, err)
	require.Equal(t, "admin", record.Role)

	events, err := reopened.TelemetryStore(ctx)
	require.NoError(t, err)
	event, err := events.GetEventByID(ctx, "registry-event")
	require.NoError(t, err)
	require.NotNil(t, event)
	require.Equal(t, "SEMANTIC_SQLI", event.RuleID)
}

func TestRegistry_DistinctStores(t *testing.T) {
	ctx := context.Background()

	reg, err := NewRegistry(StorageConfig{
		Stores: map[string]StoreConfig{
			"ctrl_store": {
				Driver: "sqlite",
				DSN:    "file:distinct_ctrl.db?mode=memory",
			},
			"telem_store": {
				Driver: "sqlite",
				DSN:    "file:distinct_telem.db?mode=memory",
			},
		},
		Control:   "ctrl_store",
		Telemetry: "telem_store",
	})
	require.NoError(t, err)
	defer reg.Close()

	cs, err := reg.ControlStore(ctx)
	require.NoError(t, err)
	require.NotNil(t, cs)

	ts, err := reg.TelemetryStore(ctx)
	require.NoError(t, err)
	require.NotNil(t, ts)

	// Distinct pools for each store
	require.Len(t, reg.pools, 2)
	require.NotNil(t, reg.pools["ctrl_store"])
	require.NotNil(t, reg.pools["telem_store"])
}

func TestRegistry_UnconfiguredStoreError(t *testing.T) {
	ctx := context.Background()

	reg, err := NewRegistry(StorageConfig{
		Stores: map[string]StoreConfig{
			"known": {Driver: "sqlite", DSN: "file:test.db"},
		},
		Control: "non_existent",
	})
	require.NoError(t, err)
	defer reg.Close()

	_, err = reg.ControlStore(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unconfigured store")
}

func TestOpenControlStore_Helper(t *testing.T) {
	ctx := context.Background()

	cs, err := OpenControlStore(ctx, "sqlite", "file:open_helper.db?mode=memory")
	require.NoError(t, err)
	require.NotNil(t, cs)
	defer cs.Close()

	apps, err := cs.ListApps(ctx)
	require.NoError(t, err)
	require.Empty(t, apps)
}

func TestOpenTelemetryStore_Helper(t *testing.T) {
	ctx := context.Background()

	ts, err := OpenTelemetryStore(ctx, "sqlite", "file:open_telem_helper.db?mode=memory", 24*time.Hour, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, ts)
	defer ts.Close()

	n, err := ts.Prune(ctx, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
}
