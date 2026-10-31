package sqlite

import (
	"context"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStore_RuleCatalogAndWAFPolicy(t *testing.T) {
	ctx := context.Background()
	store, err := InitDB("file:test_catalog_" + uuid.New().String() + ".db?mode=memory")
	require.NoError(t, err)
	defer store.Close()

	// Rule packs: create, read, update, list.
	pack := control.RulePackRecord{
		ID:        "pack-1",
		Name:      "Corp Rules",
		Version:   "1.0.0",
		Type:      control.PackTypeNative,
		Priority:  10,
		Enabled:   true,
		RulesJSON: `[{"id":"r1","name":"R1","category":"rce","matches":[{"field":"any","token":"evil"}]}]`,
		FilesJSON: `{}`,
		Checksum:  "abc",
	}
	require.NoError(t, store.UpsertRulePack(ctx, pack))

	got, err := store.GetRulePack(ctx, "pack-1")
	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, 10, got.Priority)
	require.Equal(t, control.PackTypeNative, got.Type)

	pack.Enabled = false
	pack.Priority = 5
	require.NoError(t, store.UpsertRulePack(ctx, pack))
	packs, err := store.ListRulePacks(ctx)
	require.NoError(t, err)
	require.Len(t, packs, 1)
	require.False(t, packs[0].Enabled)
	require.Equal(t, 5, packs[0].Priority)

	// Per-rule overrides: nullable enabled, severity-only rows, delete.
	disabled := false
	require.NoError(t, store.UpsertRuleOverride(ctx, control.RuleOverrideRecord{
		CanonicalID: "cve:CVE-2021-0001",
		Enabled:     &disabled,
		Action:      control.RuleActionOff,
		Severity:    control.SeverityCritical,
	}))
	override, err := store.GetRuleOverride(ctx, "cve:CVE-2021-0001")
	require.NoError(t, err)
	require.NotNil(t, override.Enabled)
	require.False(t, *override.Enabled)
	require.Equal(t, control.RuleActionOff, override.Action)

	require.NoError(t, store.UpsertRuleOverride(ctx, control.RuleOverrideRecord{
		CanonicalID: "crs:942100",
		Severity:    control.SeverityHigh,
	}))
	severityOnly, err := store.GetRuleOverride(ctx, "crs:942100")
	require.NoError(t, err)
	require.Nil(t, severityOnly.Enabled)

	overrides, err := store.ListRuleOverrides(ctx)
	require.NoError(t, err)
	require.Len(t, overrides, 2)

	// Global and per-site policies.
	crsEnabled := true
	paranoia := 2
	inbound := 3
	outbound := 2
	require.NoError(t, store.UpsertWAFPolicy(ctx, control.WAFPolicyRecord{
		ID:                   "global",
		Scope:                control.PolicyScopeGlobal,
		DetectionMode:        control.DetectionModeAlert,
		Sensitivity:          control.SensitivityHigh,
		SemanticOverrides:    `{"xss":"strict"}`,
		CRSEnabled:           &crsEnabled,
		CRSParanoiaLevel:     &paranoia,
		CRSInboundThreshold:  &inbound,
		CRSOutboundThreshold: &outbound,
		DisabledPackIDs:      `["pack-1"]`,
	}))
	policy, err := store.GetWAFPolicy(ctx, control.PolicyScopeGlobal, "")
	require.NoError(t, err)
	require.Equal(t, control.DetectionModeAlert, policy.DetectionMode)
	require.Equal(t, control.SensitivityHigh, policy.Sensitivity)
	require.NotNil(t, policy.CRSEnabled)
	require.True(t, *policy.CRSEnabled)
	require.NotNil(t, policy.CRSParanoiaLevel)
	require.Equal(t, 2, *policy.CRSParanoiaLevel)

	require.NoError(t, store.UpsertWAFPolicy(ctx, control.WAFPolicyRecord{
		ID:            "app:app-1",
		Scope:         control.PolicyScopeApp,
		AppID:         "app-1",
		DetectionMode: control.DetectionModeOff,
		Sensitivity:   control.SensitivityInherit,
	}))
	policies, err := store.ListWAFPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, policies, 2)

	// Deletes.
	require.NoError(t, store.DeleteWAFPolicy(ctx, control.PolicyScopeApp, "app-1"))
	require.NoError(t, store.DeleteRuleOverride(ctx, "crs:942100"))
	require.NoError(t, store.DeleteRulePack(ctx, "pack-1"))
	require.NoError(t, store.ClearRuleOverrides(ctx))

	_, err = store.GetRulePack(ctx, "pack-1")
	require.Error(t, err)
	remaining, err := store.ListRuleOverrides(ctx)
	require.NoError(t, err)
	require.Empty(t, remaining)
}
