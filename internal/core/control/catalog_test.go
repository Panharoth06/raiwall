package control_test

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/stretchr/testify/require"
)

func TestBuildRuleCatalog_MergesSourcesAndOverrides(t *testing.T) {
	snap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	disabled := false
	snap.RuleOverrides = map[string]*control.RuleOverrideSnapshot{
		"cve:CVE-2021-44228": {Enabled: &disabled, Action: control.RuleActionOff},
		"semantic:sql_inj":   {Severity: control.SeverityCritical},
	}
	snap.RulePacks = []*control.RulePackSnapshot{{
		ID:      "pack-1",
		Name:    "Custom Pack",
		Version: "1.0.0",
		Type:    control.PackTypeNative,
		Enabled: true,
		Rules: []cve.Signature{{
			ID:       "custom-1",
			Name:     "Custom rule",
			Category: "rce",
			Matches:  []cve.TokenRef{{Field: cve.FieldAny, Token: "evil"}},
		}},
	}}

	items := control.BuildRuleCatalog(snap)
	byID := make(map[string]control.RuleCatalogItem, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}

	semantic, ok := byID["semantic:sql_inj"]
	require.True(t, ok)
	require.True(t, semantic.Overridden)
	require.Equal(t, control.SeverityCritical, semantic.Severity)

	log4shell, ok := byID["cve:CVE-2021-44228"]
	require.True(t, ok)
	require.False(t, log4shell.Enabled)
	require.Equal(t, control.RuleActionOff, log4shell.Action)

	packRule, ok := byID["pack:pack-1:custom-1"]
	require.True(t, ok)
	require.Equal(t, control.RuleSourcePack, packRule.Source)
	require.Equal(t, "pack-1", packRule.PackID)
	require.True(t, packRule.Enabled)

	filtered, total, _ := control.FilterRuleCatalog(items, control.RuleCatalogQuery{
		Source: control.RuleSourcePack,
	})
	require.Equal(t, 1, total)
	require.Len(t, filtered, 1)
	require.Equal(t, "pack:pack-1:custom-1", filtered[0].ID)
}

func TestSnapshotInnerRuleState_AlertOnly(t *testing.T) {
	previous := control.LoadSnapshot()
	defer control.SetActiveSnapshot(previous)

	snap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	snap.RuleOverrides = map[string]*control.RuleOverrideSnapshot{
		"cve:CVE-ALERT":  {Action: control.RuleActionAlert},
		"pack:p1:rule-1": {Action: control.RuleActionAlert},
	}
	control.SetActiveSnapshot(snap)

	state := control.SnapshotInnerRuleState()
	require.NotNil(t, state)
	require.True(t, state.IsAudit("CVE-ALERT"))
	require.True(t, state.IsAudit("p1:rule-1"))
	require.False(t, state.IsAudit("CVE-OTHER"))
}
