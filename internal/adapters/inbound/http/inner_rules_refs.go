package api

import (
	"context"
	"encoding/json"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

// innerRuleRef is the resolved catalog identity for one virtual patch.
type innerRuleRef struct {
	Rule      cve.Signature
	Canonical string
	PackID    string
	PackName  string
	Enabled   bool
}

// loadInnerRuleRefs merges bundled CVE rules with persisted native packs and
// applies stored overrides plus the legacy disabled table.
func (s *Server) loadInnerRuleRefs(ctx context.Context) ([]innerRuleRef, error) {
	packs, err := s.store.ListRulePacks(ctx)
	if err != nil {
		return nil, err
	}
	overrides, err := s.store.ListRuleOverrides(ctx)
	if err != nil {
		return nil, err
	}
	overrideByID := make(map[string]control.RuleOverrideRecord, len(overrides))
	for _, override := range overrides {
		overrideByID[override.CanonicalID] = override
	}
	legacy, err := s.store.ListDisabledInnerRules(ctx)
	if err != nil {
		return nil, err
	}
	legacyDisabled := make(map[string]struct{}, len(legacy))
	for _, id := range legacy {
		legacyDisabled[id] = struct{}{}
	}

	bundled, err := cve.BundledRules()
	if err != nil {
		return nil, err
	}
	refs := make([]innerRuleRef, 0, len(bundled)+64)
	for _, rule := range bundled {
		canonical := control.CanonicalRuleID(control.RuleSourceCVE, rule.ID)
		_, isLegacyDisabled := legacyDisabled[rule.ID]
		enabled := effectiveRuleEnabled(true, isLegacyDisabled, overrideByID[canonical])
		refs = append(refs, innerRuleRef{
			Rule:      rule,
			Canonical: canonical,
			PackID:    "cve-bundled",
			PackName:  "Raiwall Core CVE Virtual Patches",
			Enabled:   enabled,
		})
	}
	for _, pack := range packs {
		if pack.Type != control.PackTypeNative {
			continue
		}
		for _, rule := range decodePackRules(pack.RulesJSON) {
			canonical := control.CanonicalRuleID(control.RuleSourcePack, pack.ID+":"+rule.ID)
			enabled := effectiveRuleEnabled(pack.Enabled, false, overrideByID[canonical])
			refs = append(refs, innerRuleRef{
				Rule:      rule,
				Canonical: canonical,
				PackID:    pack.ID,
				PackName:  pack.Name,
				Enabled:   enabled,
			})
		}
	}
	return refs, nil
}

func (s *Server) findInnerRuleRef(ctx context.Context, ruleID string) (innerRuleRef, bool, error) {
	refs, err := s.loadInnerRuleRefs(ctx)
	if err != nil {
		return innerRuleRef{}, false, err
	}
	for _, ref := range refs {
		if ref.Rule.ID == ruleID {
			return ref, true, nil
		}
	}
	return innerRuleRef{}, false, nil
}

func effectiveRuleEnabled(defaultEnabled, legacyDisabled bool, override control.RuleOverrideRecord) bool {
	enabled := defaultEnabled && !legacyDisabled
	if override.Enabled != nil {
		enabled = *override.Enabled
	}
	switch control.NormalizePolicyValue(override.Action) {
	case control.RuleActionOff:
		enabled = false
	case control.RuleActionAlert, control.RuleActionBlock:
		enabled = true
	}
	return enabled
}

func decodePackRules(raw string) []cve.Signature {
	if raw == "" || raw == "[]" {
		return nil
	}
	var rules []cve.Signature
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil
	}
	return rules
}

func countPackRules(raw string) int {
	return len(decodePackRules(raw))
}
