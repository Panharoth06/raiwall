package control_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func newCatalogStore(t *testing.T) *sqlite.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:test_catalog_compile_%d.db", time.Now().UnixNano())
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	return store
}

func TestCompiler_LoadsRuleCatalogAndPolicy(t *testing.T) {
	store := newCatalogStore(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.CreateApp(ctx, control.SiteApp{
		ID:        "app-1",
		Name:      "Catalog App",
		Hostnames: `["catalog.test"]`,
		Mode:      "defense",
		Upstreams: `[{"dial":"127.0.0.1:8080"}]`,
		CreatedAt: now,
		UpdatedAt: now,
	}))
	require.NoError(t, store.UpsertRulePack(ctx, control.RulePackRecord{
		ID:        "pack-1",
		Name:      "Catalog Pack",
		Version:   "1.0.0",
		Type:      control.PackTypeNative,
		Enabled:   true,
		RulesJSON: `[{"id":"CVE-PACK-1","name":"Pack rule","category":"rce","matches":[{"field":"any","token":"evil"}]}]`,
		FilesJSON: `{}`,
	}))

	disabled := false
	require.NoError(t, store.UpsertRuleOverride(ctx, control.RuleOverrideRecord{
		CanonicalID: "cve:CVE-TEST",
		Enabled:     &disabled,
		Action:      control.RuleActionOff,
	}))
	require.NoError(t, store.SetInnerRuleDisabled(ctx, "CVE-LEGACY", true))

	require.NoError(t, store.UpsertWAFPolicy(ctx, control.WAFPolicyRecord{
		ID:                "global",
		Scope:             control.PolicyScopeGlobal,
		DetectionMode:     control.DetectionModeAlert,
		Sensitivity:       control.SensitivityHigh,
		SemanticOverrides: `{}`,
		DisabledPackIDs:   `[]`,
	}))
	require.NoError(t, store.UpsertWAFPolicy(ctx, control.WAFPolicyRecord{
		ID:                "app:app-1",
		Scope:             control.PolicyScopeApp,
		AppID:             "app-1",
		DetectionMode:     control.DetectionModeOff,
		Sensitivity:       control.SensitivityInherit,
		SemanticOverrides: `{}`,
		DisabledPackIDs:   `[]`,
	}))

	snap, err := control.CompileSnapshot(ctx, store)
	require.NoError(t, err)
	require.Len(t, snap.RulePacks, 1)
	require.Len(t, snap.RulePacks[0].Rules, 1)
	require.NotNil(t, snap.RuleOverrides["cve:CVE-TEST"])
	require.Contains(t, snap.InnerRulesDisabled, "CVE-TEST")
	require.Contains(t, snap.InnerRulesDisabled, "CVE-LEGACY")
	require.NotNil(t, snap.WAFPolicy)
	require.Equal(t, control.DetectionModeAlert, snap.WAFPolicy.DetectionMode)
	require.NotNil(t, snap.Apps["app-1"].WAFPolicy)

	resolved := snap.ResolveWAFPolicyFor("app-1")
	require.Equal(t, control.DetectionModeOff, resolved.DetectionMode)
	require.Equal(t, control.SensitivityHigh, resolved.Sensitivity)
}

func TestCompiler_RejectsInvalidNativePack(t *testing.T) {
	store := newCatalogStore(t)
	defer store.Close()
	ctx := context.Background()

	require.NoError(t, store.UpsertRulePack(ctx, control.RulePackRecord{
		ID:        "pack-bad",
		Name:      "Bad Pack",
		Version:   "1.0.0",
		Type:      control.PackTypeNative,
		Enabled:   true,
		RulesJSON: `[{"id":"bad-rule","name":"Missing matches"}]`,
		FilesJSON: `{}`,
	}))

	_, err := control.CompileSnapshot(ctx, store)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no match tokens")
}
