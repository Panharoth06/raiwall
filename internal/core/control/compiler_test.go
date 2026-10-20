package control

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/stretchr/testify/require"
)

func TestCompiler_CompileAndValidate(t *testing.T) {
	dsn := fmt.Sprintf("file:test_compiler_%d.db", time.Now().UnixNano())
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "app-1",
		Name:                "API Gateway",
		Hostnames:           `["api.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"127.0.0.1:8080","weight":1}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "Blocked",
		OfflineStatusCode:   503,
		OfflineResponseBody: "Offline",
		CustomHeaders:       `{"X-Protected":"Raiwall"}`,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	err = store.CreateException(ctx, sqlite.CreateExceptionParams{
		ID:          "exc-1",
		Description: "Bypass search",
		Host:        "api.example.com",
		PathRegex:   "^/search",
		PathPrefix:  "/search",
		Method:      "GET",
		Location:    "Query",
		ParamName:   "q",
		ParamRegex:  "",
		RuleID:      "SEMANTIC_SQLI",
		IsActive:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	err = store.CreateACLRule(ctx, sqlite.CreateACLRuleParams{
		ID:          "acl-1",
		Name:        "Block Tor",
		Expression:  `in_cidr(client_ip, "192.168.1.0/24")`,
		Action:      "block",
		Priority:    10,
		StatusCode:  403,
		RedirectUrl: "",
		IsActive:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	snap, err := CompileSnapshot(ctx, store)
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.Len(t, snap.Apps, 1)
	require.Len(t, snap.Exceptions, 1)
	require.Len(t, snap.ACLRules, 1)

	app, found := snap.GetAppForHost("api.example.com")
	require.True(t, found)
	require.Equal(t, "API Gateway", app.Name)
}

func TestCompiler_PreFlightValidationFailure(t *testing.T) {
	dsn := fmt.Sprintf("file:test_val_fail_%d.db", time.Now().UnixNano())
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	initialSnap := NewConfigSnapshot(1, ModeDefense, []*AppConfig{
		{
			ID:        "app-valid",
			Name:      "Valid App",
			Hostnames: []string{"valid.example.com"},
			Mode:      ModeDefense,
			Upstreams: []UpstreamTarget{{Dial: "127.0.0.1:8080"}},
		},
	})
	StoreSnapshot(initialSnap)
	activeBefore := LoadSnapshot()
	require.Equal(t, "app-valid", activeBefore.Apps["app-valid"].ID)

	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "app-bad",
		Name:                "Bad App",
		Hostnames:           `["bad.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"not-a-valid-address-no-port"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	err = store.CreateACLRule(ctx, sqlite.CreateACLRuleParams{
		ID:          "acl-bad",
		Name:        "Syntax Error Rule",
		Expression:  `this is syntax error +++ `,
		Action:      "block",
		Priority:    1,
		StatusCode:  403,
		RedirectUrl: "",
		IsActive:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	err = store.CreateException(ctx, sqlite.CreateExceptionParams{
		ID:          "exc-bad",
		Description: "Bad regex",
		Host:        "*",
		PathRegex:   "[a-z(",
		Method:      "GET",
		Location:    "Query",
		ParamName:   "id",
		RuleID:      "*",
		IsActive:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	snap, err := CompileSnapshot(ctx, store)
	require.Error(t, err)
	require.Nil(t, snap)

	deployed, err := DeploySnapshot(ctx, store, "admin", "Attempt invalid deploy")
	require.Error(t, err)
	require.Nil(t, deployed)

	activeAfter := LoadSnapshot()
	require.Equal(t, activeBefore.Version, activeAfter.Version)
	require.Equal(t, "app-valid", activeAfter.Apps["app-valid"].ID)
	_, found := activeAfter.Apps["app-bad"]
	require.False(t, found)
}

func TestCompiler_DeployAndRollback(t *testing.T) {
	dsn := fmt.Sprintf("file:test_deploy_rb_%d.db", time.Now().UnixNano())
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "app-v1",
		Name:                "App V1",
		Hostnames:           `["v1.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"127.0.0.1:8001"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	snap1, err := DeploySnapshot(ctx, store, "alice", "Release v1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), snap1.Version)
	require.Equal(t, snap1, LoadSnapshot())

	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "app-v2",
		Name:                "App V2",
		Hostnames:           `["v2.example.com"]`,
		Mode:                "audit",
		Upstreams:           `[{"dial":"127.0.0.1:8002"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now.Add(time.Minute),
		UpdatedAt:           now.Add(time.Minute),
	})
	require.NoError(t, err)

	snap2, err := DeploySnapshot(ctx, store, "bob", "Release v2 with app-v2")
	require.NoError(t, err)
	require.Equal(t, uint64(2), snap2.Version)
	require.Equal(t, snap2, LoadSnapshot())
	require.Len(t, LoadSnapshot().Apps, 2)

	restored, err := RollbackToVersion(ctx, store, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), restored.Version)

	active := LoadSnapshot()
	require.Equal(t, uint64(1), active.Version)
	require.Len(t, active.Apps, 1)
	_, found := active.GetAppForHost("v1.example.com")
	require.True(t, found)
	_, found = active.GetAppForHost("v2.example.com")
	require.False(t, found)

	history, err := ListSnapshotHistory(ctx, store)
	require.NoError(t, err)
	require.Len(t, history, 2)
}

func TestCompiler_ConcurrentReadsAndAtomicRollback(t *testing.T) {
	dsn := fmt.Sprintf("file:test_concurrent_%d.db", time.Now().UnixNano())
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "app-concurrent",
		Name:                "Concurrent App",
		Hostnames:           `["conc.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"127.0.0.1:8080"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	_, err = DeploySnapshot(ctx, store, "admin", "Base snapshot")
	require.NoError(t, err)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					s := LoadSnapshot()
					if s != nil {
						_, _ = s.GetAppForHost("conc.example.com")
					}
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}

	for i := 0; i < 5; i++ {
		_, err = DeploySnapshot(ctx, store, "admin", fmt.Sprintf("Deploy %d", i))
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)

		_, err = RollbackToVersion(ctx, store, 1)
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	close(stopCh)
	wg.Wait()
}
