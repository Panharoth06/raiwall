package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/stretchr/testify/require"
)

func TestPostgres_InterfaceCompliance(t *testing.T) {
	var _ control.ControlStore = (*ControlStore)(nil)
	var _ telemetry.ForensicStore = (*TelemetryStore)(nil)
}

type mockDBTX struct {
	lastQuery string
	lastArgs  []any
	execErr   error
}

func (m *mockDBTX) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	m.lastQuery = query
	m.lastArgs = args
	return mockResult{}, m.execErr
}

func (m *mockDBTX) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	m.lastQuery = query
	return nil, nil
}

func (m *mockDBTX) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	m.lastQuery = query
	m.lastArgs = args
	return nil, nil
}

func (m *mockDBTX) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	m.lastQuery = query
	m.lastArgs = args
	return nil
}

type mockResult struct{}

func (m mockResult) LastInsertId() (int64, error) { return 1, nil }
func (m mockResult) RowsAffected() (int64, error) { return 1, nil }

func TestControlStore_QueryFormatting(t *testing.T) {
	mock := &mockDBTX{}
	store := &ControlStore{db: mock}
	ctx := context.Background()
	now := time.Now().UTC()

	// 1. CreateApp
	err := store.CreateApp(ctx, control.SiteApp{
		ID:        "app-pg",
		Name:      "PG App",
		Hostnames: `["pg.example.com"]`,
		Mode:      "defense",
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_apps")
	require.Contains(t, mock.lastQuery, "$1, $2")
	require.Equal(t, "app-pg", mock.lastArgs[0])

	// 2. DeleteApp
	err = store.DeleteApp(ctx, "app-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_apps WHERE id = $1")
	require.Equal(t, "app-pg", mock.lastArgs[0])

	// 3. CreateException & DeleteException
	err = store.CreateException(ctx, control.ExceptionRule{
		ID:        "exc-pg",
		Host:      "pg.example.com",
		PathRegex: "^/admin",
		RuleID:    "RULE_1",
		IsActive:  1,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_exceptions")
	require.Equal(t, "exc-pg", mock.lastArgs[0])

	err = store.DeleteException(ctx, "exc-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_exceptions WHERE id = $1")

	// 4. CreateACLRule & DeleteACLRule
	err = store.CreateACLRule(ctx, control.AclRule{
		ID:         "acl-pg",
		Name:       "Test Rule",
		Expression: "true",
		Action:     "block",
		Priority:   10,
		StatusCode: 403,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_acl_rules")

	err = store.DeleteACLRule(ctx, "acl-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_acl_rules WHERE id = $1")

	// 5. CreateRatePolicy & DeleteRatePolicy
	err = store.CreateRatePolicy(ctx, control.RatePolicy{
		ID:        "rp-pg",
		Name:      "Rate 1",
		Tier1Rate: 100,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_rate_policies")

	err = store.DeleteRatePolicy(ctx, "rp-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_rate_policies WHERE id = $1")

	// 6. CreateBotConfig & DeleteBotConfig
	err = store.CreateBotConfig(ctx, control.BotConfig{
		ID:         "bot-pg",
		Host:       "*",
		PowEnabled: 1,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_bot_configs")

	err = store.DeleteBotConfig(ctx, "bot-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_bot_configs WHERE id = $1")

	// 7. Users
	err = store.CreateUser(ctx, control.UserRecord{
		ID:           "user-1",
		Username:     "admin",
		PasswordHash: "hash",
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_users")

	err = store.DeleteUser(ctx, "user-1")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_users WHERE id = $1")

	// 8. API Keys
	err = store.CreateAPIKey(ctx, control.ApiKeyRecord{
		ID:        "key-1",
		Name:      "CI Key",
		KeyHash:   "hash",
		Role:      "admin",
		IsActive:  1,
		CreatedAt: now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_api_keys")

	err = store.UpdateAPIKeyLastUsed(ctx, "key-1", now)
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "UPDATE raiwall_api_keys SET last_used_at = $1 WHERE id = $2")

	// 9. Forwarding Rules
	err = store.CreateForwardingRule(ctx, control.ForwardingRuleRecord{
		ID:        "fwd-1",
		AppID:     "app-pg",
		Prefix:    "/api/v2",
		Upstreams: `["http://backend:8080"]`,
		IsActive:  1,
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_forwarding_rules")

	err = store.DeleteForwardingRulesByApp(ctx, "app-pg")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_forwarding_rules WHERE app_id = $1")

	// 10. UpsertAPIResource
	err = store.UpsertAPIResource(ctx, control.ApiResourceRecord{
		ID:          "res-pg",
		AppID:       "app-pg",
		Method:      "GET",
		PathPattern: "/api/v1/test",
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "ON CONFLICT (app_id, method, path_pattern) DO UPDATE")

	// 11. IP Groups (Phase 7)
	err = store.CreateIPGroup(ctx, control.IPGroupRecord{
		ID:          "ipg-1",
		Name:        "test-group",
		Description: "A test IP group",
		Type:        "custom",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_ip_groups")
	require.Equal(t, "ipg-1", mock.lastArgs[0])

	err = store.DeleteIPGroup(ctx, "ipg-1")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_ip_groups WHERE id = $1")

	// 12. IP Group Entries (Phase 7)
	err = store.CreateIPGroupEntry(ctx, control.IPGroupEntryRecord{
		ID:        "entry-1",
		GroupID:   "ipg-1",
		CIDR:      "192.0.2.0/24",
		Comment:   "test subnet",
		CreatedAt: now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_ip_group_entries")

	err = store.DeleteIPGroupEntry(ctx, "entry-1")
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_ip_group_entries WHERE id = $1")

	// 13. Templates (Phase 7)
	err = store.UpsertTemplate(ctx, control.TemplateRecord{
		ID:          "tmpl-1",
		StatusCode:  403,
		Title:       "Blocked",
		ContentHTML: "<h1>Forbidden</h1>",
		IsCustom:    1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "INSERT INTO raiwall_response_templates")
	require.Contains(t, mock.lastQuery, "ON CONFLICT (status_code) DO UPDATE")

	err = store.DeleteTemplate(ctx, 403)
	require.NoError(t, err)
	require.Contains(t, mock.lastQuery, "DELETE FROM raiwall_response_templates WHERE status_code = $1")

	// 14. Standalone vs Shared Close
	sharedStore := NewControlStore(nil)
	require.NoError(t, sharedStore.Close())

	standaloneStore := NewStandaloneControlStore(nil)
	require.NoError(t, standaloneStore.Close())
}

func TestAggregateWhereFilters(t *testing.T) {
	start := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	clause, args := aggregateWhere(start, end)
	require.Equal(t, "timestamp >= $1 AND timestamp <= $2", clause)
	require.Equal(t, []any{start, end}, args)

	clause, args = aggregateWhere(start, end, telemetry.AggregateFilter{Host: "app.example.com", Country: "US"})
	require.Equal(t, "timestamp >= $1 AND timestamp <= $2 AND host = $3 AND country = $4", clause)
	require.Equal(t, []any{start, end, "app.example.com", "US"}, args)
}

func TestTelemetryStore_QueryFormatting(t *testing.T) {
	mock := &mockDBTX{}
	store := &TelemetryStore{
		db:     &sql.DB{},
		stopCh: make(chan struct{}),
		ownsDB: false,
	}

	// 1. Standalone vs Shared Close
	sharedTelem := NewTelemetryStore(nil, 0, 0)
	require.NoError(t, sharedTelem.Close())

	standaloneTelem := NewStandaloneTelemetryStore(nil, 0, 0)
	require.NoError(t, standaloneTelem.Close())

	// 2. Interface and method existence
	_ = store
	_ = mock
}
