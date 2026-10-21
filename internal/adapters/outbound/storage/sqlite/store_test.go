package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestStore_InitAndPragmas(t *testing.T) {
	dsn := fmt.Sprintf("file:test_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	require.NotNil(t, store.DB())
	require.NotNil(t, store.Queries)
}

func TestStore_AppsCRUD(t *testing.T) {
	dsn := fmt.Sprintf("file:test_apps_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Create
	err = store.CreateApp(ctx, control.SiteApp{
		ID:                  "app-1",
		Name:                "Payment Service",
		Hostnames:           `["pay.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"10.0.0.1:8080","weight":1}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "Blocked by Raiwall",
		OfflineStatusCode:   503,
		OfflineResponseBody: "Maintenance",
		CustomHeaders:       `{"X-Protected-By":"Raiwall"}`,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	// 2. Get
	app, err := store.GetApp(ctx, "app-1")
	require.NoError(t, err)
	require.Equal(t, "Payment Service", app.Name)
	require.Equal(t, "defense", app.Mode)

	// 3. List
	apps, err := store.ListApps(ctx)
	require.NoError(t, err)
	require.Len(t, apps, 1)

	// 4. Update
	err = store.UpdateApp(ctx, control.SiteApp{
		ID:                  "app-1",
		Name:                "Payment Gateway",
		Hostnames:           `["pay.example.com","checkout.example.com"]`,
		Mode:                "audit",
		Upstreams:           `[{"dial":"10.0.0.1:8080","weight":2}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "Audit Mode",
		OfflineStatusCode:   503,
		OfflineResponseBody: "Maintenance",
		CustomHeaders:       `{"X-Mode":"Audit"}`,
		UpdatedAt:           now.Add(time.Minute),
	})
	require.NoError(t, err)

	updated, err := store.GetApp(ctx, "app-1")
	require.NoError(t, err)
	require.Equal(t, "Payment Gateway", updated.Name)
	require.Equal(t, "audit", updated.Mode)

	// 5. Delete
	err = store.DeleteApp(ctx, "app-1")
	require.NoError(t, err)

	_, err = store.GetApp(ctx, "app-1")
	require.Error(t, err)
}

func TestStore_ExceptionsCRUD(t *testing.T) {
	dsn := fmt.Sprintf("file:test_exc_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateException(ctx, control.ExceptionRule{
		ID:          "exc-1",
		Description: "Bypass false-positive in search query",
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

	exc, err := store.GetException(ctx, "exc-1")
	require.NoError(t, err)
	require.Equal(t, "api.example.com", exc.Host)

	activeList, err := store.ListActiveExceptions(ctx)
	require.NoError(t, err)
	require.Len(t, activeList, 1)

	err = store.DeleteException(ctx, "exc-1")
	require.NoError(t, err)
}

func TestStore_ACLRulesCRUD(t *testing.T) {
	dsn := fmt.Sprintf("file:test_acl_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateACLRule(ctx, control.AclRule{
		ID:          "acl-1",
		Name:        "Block Tor Exit Nodes",
		Expression:  `in_feed(client_ip, "tor_exit")`,
		Action:      "block",
		Priority:    100,
		StatusCode:  403,
		RedirectUrl: "",
		IsActive:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)

	rule, err := store.GetACLRule(ctx, "acl-1")
	require.NoError(t, err)
	require.Equal(t, "Block Tor Exit Nodes", rule.Name)
	require.Equal(t, int64(100), rule.Priority)

	rules, err := store.ListActiveACLRules(ctx)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	err = store.DeleteACLRule(ctx, "acl-1")
	require.NoError(t, err)
}

func TestStore_SnapshotsAndRollback(t *testing.T) {
	dsn := fmt.Sprintf("file:test_snap_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	snap1, err := store.CreateSnapshot(ctx, control.ConfigSnapshotRecord{
		SnapshotData: `{"version":1,"apps":{}}`,
		Author:       "admin",
		Description:  "Initial deployment",
		CreatedAt:    now,
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), snap1.Version)

	snap2, err := store.CreateSnapshot(ctx, control.ConfigSnapshotRecord{
		SnapshotData: `{"version":2,"apps":{"app-1":{}}}`,
		Author:       "admin",
		Description:  "Added app-1",
		CreatedAt:    now.Add(time.Minute),
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), snap2.Version)

	latest, err := store.GetLatestSnapshot(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), latest.Version)

	byVer, err := store.GetSnapshotByVersion(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, int64(1), byVer.Version)
	require.Equal(t, "Initial deployment", byVer.Description)
}

func TestStore_UsersAndAPIKeys(t *testing.T) {
	dsn := fmt.Sprintf("file:test_users_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Users
	err = store.CreateUser(ctx, control.UserRecord{
		ID:           "u-1",
		Username:     "alice",
		PasswordHash: "$2a$12$hashedpassword",
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	u, err := store.GetUserByUsername(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, "admin", u.Role)

	// API Keys
	err = store.CreateAPIKey(ctx, control.ApiKeyRecord{
		ID:        "k-1",
		Name:      "CI/CD Deployer",
		KeyHash:   "sha256_mock_key_hash",
		Role:      "admin",
		ExpiresAt: sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		IsActive:  1,
		CreatedAt: now,
	})
	require.NoError(t, err)

	k, err := store.GetAPIKeyByHash(ctx, "sha256_mock_key_hash")
	require.NoError(t, err)
	require.Equal(t, "CI/CD Deployer", k.Name)
}

func TestStore_TransactionRollback(t *testing.T) {
	dsn := fmt.Sprintf("file:test_tx_%d.db", time.Now().UnixNano())
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Transaction that fails and rolls back
	err = store.WithTx(ctx, func(txStore control.ControlStore) error {
		createErr := txStore.CreateApp(ctx, control.SiteApp{
			ID:                  "app-rollback",
			Name:                "Rollback Me",
			Hostnames:           `["rb.example.com"]`,
			Mode:                "defense",
			Upstreams:           "[]",
			BlockStatusCode:     403,
			BlockResponseBody:   "",
			OfflineStatusCode:   503,
			OfflineResponseBody: "",
			CustomHeaders:       "{}",
			CreatedAt:           now,
			UpdatedAt:           now,
		})
		if createErr != nil {
			return createErr
		}

		// Force error to trigger rollback
		return errors.New("simulated error")
	})
	require.Error(t, err)

	// Verify app was NOT persisted due to rollback
	_, err = store.GetApp(ctx, "app-rollback")
	require.Error(t, err)
}
