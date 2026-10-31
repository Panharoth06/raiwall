package control

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

// compileRulePacks loads persisted imported packs into self-contained snapshot
// records. Content is retained so rollback can reproduce the exact ruleset.
func compileRulePacks(ctx context.Context, store ControlStore) ([]*RulePackSnapshot, error) {
	records, err := store.ListRulePacks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load rule packs: %w", err)
	}
	if len(records) > MaxRulePacks {
		return nil, fmt.Errorf("too many rule packs: %d (max %d)", len(records), MaxRulePacks)
	}

	packs := make([]*RulePackSnapshot, 0, len(records))
	for _, rec := range records {
		rules, err := decodeNativeRules(rec.RulesJSON)
		if err != nil {
			return nil, fmt.Errorf("rule pack %q: %w", rec.ID, err)
		}
		files, err := decodePackFiles(rec.FilesJSON)
		if err != nil {
			return nil, fmt.Errorf("rule pack %q: %w", rec.ID, err)
		}
		packs = append(packs, &RulePackSnapshot{
			ID:             rec.ID,
			Name:           rec.Name,
			Version:        rec.Version,
			Type:           rec.Type,
			Priority:       rec.Priority,
			Enabled:        rec.Enabled,
			ReplaceBuiltin: rec.ReplaceBuiltin,
			Rules:          rules,
			Directives:     rec.Directives,
			Files:          files,
			Checksum:       rec.Checksum,
		})
	}
	return packs, nil
}

// compileRuleOverrides merges the new override table with the legacy
// inner-rule toggle table. Overrides always win; the derived disabled set feeds
// the existing cve.StateSource path.
func compileRuleOverrides(
	ctx context.Context,
	store ControlStore,
	legacyDisabled []string,
) (map[string]*RuleOverrideSnapshot, map[string]struct{}, error) {
	records, err := store.ListRuleOverrides(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load rule overrides: %w", err)
	}

	overrides := make(map[string]*RuleOverrideSnapshot, len(records)+len(legacyDisabled))
	for _, rec := range records {
		if _, _, err := ParseCanonicalRuleID(rec.CanonicalID); err != nil {
			return nil, nil, fmt.Errorf("invalid rule override %q: %w", rec.CanonicalID, err)
		}
		overrides[rec.CanonicalID] = &RuleOverrideSnapshot{
			Enabled:  rec.Enabled,
			Severity: rec.Severity,
			Action:   rec.Action,
		}
	}

	// Legacy toggles become canonical overrides unless an explicit override exists.
	for _, id := range legacyDisabled {
		canonical := CanonicalRuleID(RuleSourceCVE, id)
		if _, exists := overrides[canonical]; exists {
			continue
		}
		disabled := false
		overrides[canonical] = &RuleOverrideSnapshot{Enabled: &disabled, Action: RuleActionOff}
	}

	disabled := make(map[string]struct{})
	for canonical, override := range overrides {
		source, id, err := ParseCanonicalRuleID(canonical)
		if err != nil || override == nil {
			continue
		}
		if source != RuleSourceCVE && source != RuleSourcePack {
			continue
		}
		off := (override.Enabled != nil && !*override.Enabled) ||
			NormalizePolicyValue(override.Action) == RuleActionOff
		if off {
			// Native pack rules are namespaced by pack ID at compile time.
			disabled[id] = struct{}{}
		}
	}
	return overrides, disabled, nil
}

// compileWAFPolicies loads the global and per-site detection policies.
func compileWAFPolicies(
	ctx context.Context,
	store ControlStore,
) (*WAFPolicySnapshot, map[string]*WAFPolicySnapshot, error) {
	records, err := store.ListWAFPolicies(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load waf policies: %w", err)
	}

	var global *WAFPolicySnapshot
	appPolicies := make(map[string]*WAFPolicySnapshot)
	for _, rec := range records {
		policy, err := policySnapshotFromRecord(rec)
		if err != nil {
			return nil, nil, fmt.Errorf("waf policy %q: %w", rec.ID, err)
		}
		switch rec.Scope {
		case PolicyScopeGlobal:
			global = policy
		case PolicyScopeApp:
			if rec.AppID == "" {
				return nil, nil, fmt.Errorf("app-scoped waf policy %q has no app_id", rec.ID)
			}
			appPolicies[rec.AppID] = policy
		default:
			return nil, nil, fmt.Errorf("waf policy %q has unknown scope %q", rec.ID, rec.Scope)
		}
	}
	return global, appPolicies, nil
}

func policySnapshotFromRecord(rec WAFPolicyRecord) (*WAFPolicySnapshot, error) {
	policy := &WAFPolicySnapshot{
		DetectionMode:        NormalizePolicyValue(rec.DetectionMode),
		Sensitivity:          NormalizePolicyValue(rec.Sensitivity),
		CRSEnabled:           cloneBoolPtr(rec.CRSEnabled),
		CRSParanoiaLevel:     intPtrOrZero(rec.CRSParanoiaLevel),
		CRSInboundThreshold:  intPtrOrZero(rec.CRSInboundThreshold),
		CRSOutboundThreshold: intPtrOrZero(rec.CRSOutboundThreshold),
	}
	if rec.SemanticOverrides != "" && rec.SemanticOverrides != "{}" {
		if err := json.Unmarshal([]byte(rec.SemanticOverrides), &policy.SemanticOverrides); err != nil {
			return nil, fmt.Errorf("invalid semantic_overrides JSON: %w", err)
		}
	}
	if rec.DisabledPackIDs != "" && rec.DisabledPackIDs != "[]" {
		if err := json.Unmarshal([]byte(rec.DisabledPackIDs), &policy.DisabledPacks); err != nil {
			return nil, fmt.Errorf("invalid disabled_pack_ids JSON: %w", err)
		}
	}
	return policy, nil
}

func decodeNativeRules(raw string) ([]cve.Signature, error) {
	if raw == "" || raw == "[]" {
		return nil, nil
	}
	var rules []cve.Signature
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, fmt.Errorf("invalid native rules JSON: %w", err)
	}
	return rules, nil
}

func decodePackFiles(raw string) (map[string]string, error) {
	if raw == "" || raw == "{}" {
		return nil, nil
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(raw), &files); err != nil {
		return nil, fmt.Errorf("invalid pack files JSON: %w", err)
	}
	return files, nil
}

func cloneBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func intPtrOrZero(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}
