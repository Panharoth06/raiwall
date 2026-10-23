package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func timeNowUTC() time.Time {
	return time.Now().UTC()
}

func TestStore_DetectorConfigAndAppPolicies(t *testing.T) {
	ctx := context.Background()
	dsn := "file:test_matrix_" + uuid.New().String() + ".db?mode=memory"
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	// 1. Global detector config: upsert overrides and list deterministically
	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "sql_inj", Mode: "strict", UpdatedAt: timeNowUTC(),
	}))
	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "xss", Mode: "disabled", UpdatedAt: timeNowUTC(),
	}))
	// Re-upsert to simulate an update
	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "xss", Mode: "audit", UpdatedAt: timeNowUTC(),
	}))

	records, err := store.ListDetectorConfig(ctx)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "sql_inj", records[0].Module)
	assert.Equal(t, "strict", records[0].Mode)
	assert.Equal(t, "xss", records[1].Module)
	assert.Equal(t, "audit", records[1].Mode)

	// Delete module override → next compile falls back to defaults (balance)
	require.NoError(t, store.DeleteDetectorConfig(ctx, "xss"))
	records, err = store.ListDetectorConfig(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)

	// 2. Per-app semantic policies
	app := control.SiteApp{
		ID:        uuid.New().String(),
		Name:      "policy-app",
		Hostnames: `["policy.test"]`,
		Mode:      "defense",
		Upstreams: `[{"dial":"127.0.0.1:9000"}]`,
	}
	require.NoError(t, store.CreateApp(ctx, app))

	policy := `{"sql_inj":"audit","xss":"disabled"}`
	require.NoError(t, store.UpsertAppSemanticPolicy(ctx, control.AppSemanticPolicyRecord{
		AppID: app.ID, Policy: policy, UpdatedAt: timeNowUTC(),
	}))

	policies, err := store.ListAppSemanticPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, app.ID, policies[0].AppID)
	assert.Equal(t, policy, policies[0].Policy)

	// Replace policy
	require.NoError(t, store.UpsertAppSemanticPolicy(ctx, control.AppSemanticPolicyRecord{
		AppID: app.ID, Policy: `{"ssti":"strict"}`, UpdatedAt: timeNowUTC(),
	}))
	policies, err = store.ListAppSemanticPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, `{"ssti":"strict"}`, policies[0].Policy)

	// Clear policy
	require.NoError(t, store.DeleteAppSemanticPolicy(ctx, app.ID))
	policies, err = store.ListAppSemanticPolicies(ctx)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestCompileSnapshot_SemanticMatrix(t *testing.T) {
	ctx := context.Background()
	dsn := "file:test_matrix_compile_" + uuid.New().String() + ".db?mode=memory"
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	appID := uuid.New().String()
	app := control.SiteApp{
		ID:        appID,
		Name:      "semantic-app",
		Hostnames: `["semantic.test"]`,
		Mode:      "defense",
		Upstreams: `[{"dial":"127.0.0.1:9001"}]`,
	}
	require.NoError(t, store.CreateApp(ctx, app))

	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "sql_inj", Mode: "strict", UpdatedAt: timeNowUTC(),
	}))
	require.NoError(t, store.UpsertAppSemanticPolicy(ctx, control.AppSemanticPolicyRecord{
		AppID: appID, Policy: `{"xss":"audit"}`, UpdatedAt: timeNowUTC(),
	}))

	snap, err := control.CompileSnapshot(ctx, store)
	require.NoError(t, err)
	require.NotNil(t, snap)

	// Global defaults: strict sql_inj; unset modules resolve to balance on lookup
	assert.Equal(t, waf.ModeStrict, snap.SemanticDefaults[waf.ModuleSQLInj])
	assert.NotContains(t, snap.SemanticDefaults, waf.ModuleXSS)
	assert.Equal(t, waf.ModeBalance, snap.SemanticMatrixFor("").Mode(waf.ModuleXSS))

	// Resolved app matrix: strict sql_inj + per-app audit xss
	matrix := snap.SemanticMatrixFor(appID)
	assert.Equal(t, waf.ModeStrict, matrix.Mode(waf.ModuleSQLInj))
	assert.Equal(t, waf.ModeAudit, matrix.Mode(waf.ModuleXSS))
	assert.Equal(t, waf.ModeBalance, matrix.Mode(waf.ModuleCmdInj))

	// Unknown app → global defaults only
	global := snap.SemanticMatrixFor("ghost")
	assert.Equal(t, waf.ModeStrict, global.Mode(waf.ModuleSQLInj))
	assert.Equal(t, waf.ModeBalance, global.Mode(waf.ModuleXSS))
}

func TestCompileSnapshot_RejectsInvalidSemanticConfig(t *testing.T) {
	ctx := context.Background()
	dsn := "file:test_matrix_invalid_" + uuid.New().String() + ".db?mode=memory"
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "definitely_not_a_module", Mode: "strict", UpdatedAt: timeNowUTC(),
	}))

	_, err = control.CompileSnapshot(ctx, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown semantic module")
}

func TestCompileSnapshot_RejectsInvalidMode(t *testing.T) {
	ctx := context.Background()
	dsn := "file:test_matrix_badmode_" + uuid.New().String() + ".db?mode=memory"
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
		Module: "sql_inj", Mode: "paranoid", UpdatedAt: timeNowUTC(),
	}))

	_, err = control.CompileSnapshot(ctx, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

func TestValidateSnapshot_PerAppPolicyOutOfRange(t *testing.T) {
	app := &control.AppConfig{
		ID:        "app-1",
		Name:      "bad-policy",
		Hostnames: []string{"bad.test"},
		Mode:      control.ModeDefense,
		SemanticPolicy: map[waf.Module]waf.ModuleMode{
			waf.ModuleSQLInj: waf.ModuleMode(9),
		},
	}
	snap := control.NewConfigSnapshot(1, control.ModeDefense, []*control.AppConfig{app})
	err := control.ValidateSnapshot(snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}
