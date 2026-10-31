package control

import (
	"fmt"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

// validateWAFConfig checks imported packs, per-rule overrides, and detection
// policies. Invalid content is rejected before the snapshot is persisted so a
// bad rule set can never replace a working data-plane engine.
func validateWAFConfig(snap *ConfigSnapshot) []ValidationError {
	var errs []ValidationError
	add := func(entity, id, field, reason string) {
		errs = append(errs, ValidationError{Entity: entity, ID: id, Field: field, Reason: reason})
	}

	packIDs := make(map[string]struct{}, len(snap.RulePacks))
	nameVersions := make(map[string]string, len(snap.RulePacks))
	replaceEnabled := 0
	for _, pack := range snap.RulePacks {
		if pack == nil {
			continue
		}
		if pack.ID == "" {
			add("RulePack", "", "id", "pack ID cannot be empty")
		} else if _, exists := packIDs[pack.ID]; exists {
			add("RulePack", pack.ID, "id", "duplicate pack ID")
		} else {
			packIDs[pack.ID] = struct{}{}
		}
		if pack.Name == "" {
			add("RulePack", pack.ID, "name", "pack name cannot be empty")
		} else if len(pack.Name) > MaxPackNameLn {
			add("RulePack", pack.ID, "name", fmt.Sprintf("pack name exceeds %d characters", MaxPackNameLn))
		}
		if pack.Version == "" {
			add("RulePack", pack.ID, "version", "pack version cannot be empty")
		}
		key := pack.Name + "\x00" + pack.Version
		if owner, exists := nameVersions[key]; exists {
			add("RulePack", pack.ID, "name", fmt.Sprintf("duplicate name/version already used by pack %q", owner))
		} else {
			nameVersions[key] = pack.ID
		}
		if !IsValidPackType(pack.Type) {
			add("RulePack", pack.ID, "type", fmt.Sprintf("unknown pack type %q", pack.Type))
		}
		if pack.ReplaceBuiltin {
			if pack.Type != PackTypeCRS {
				add("RulePack", pack.ID, "relation", "only crs packs may replace the embedded ruleset")
			}
			if pack.Enabled {
				replaceEnabled++
			}
		}
		if len(pack.Files) > MaxPackFiles {
			add("RulePack", pack.ID, "files", fmt.Sprintf("%d files exceeds the %d-file limit", len(pack.Files), MaxPackFiles))
		}
		if len(pack.Rules) > MaxPackRules {
			add("RulePack", pack.ID, "rules", fmt.Sprintf("%d rules exceeds the %d-rule limit", len(pack.Rules), MaxPackRules))
		}
		if size := rulePackSize(pack); size > MaxPackBytes {
			add("RulePack", pack.ID, "content", fmt.Sprintf("pack payload %d bytes exceeds the %d-byte limit", size, MaxPackBytes))
		}
		switch pack.Type {
		case PackTypeNative:
			if len(pack.Rules) == 0 && pack.Directives == "" && len(pack.Files) == 0 {
				add("RulePack", pack.ID, "rules", "native pack contains no rules")
			}
			if len(pack.Rules) > 0 {
				if _, err := cve.NewEngine(pack.Rules); err != nil {
					add("RulePack", pack.ID, "rules", err.Error())
				}
			}
		case PackTypeModsec, PackTypeCRS:
			if pack.Directives == "" && len(pack.Files) == 0 && len(pack.Rules) == 0 {
				add("RulePack", pack.ID, "content", "pack contains no directives, files, or native rules")
			}
			if pack.Directives == "" && !hasConfFile(pack.Files) {
				add("RulePack", pack.ID, "content", "pack contains no directive text or .conf file")
			}
		}
	}

	if err := validateCorazaRuleset(snap.RulePacks); err != nil {
		add("RulePack", "", "ruleset", err.Error())
	}
	if len(snap.RulePacks) > MaxRulePacks {
		add("RulePack", "", "packs", fmt.Sprintf("%d packs exceeds the %d-pack limit", len(snap.RulePacks), MaxRulePacks))
	}
	if replaceEnabled > 1 {
		add("RulePack", "", "relation", "only one enabled pack may replace the embedded CRS ruleset")
	}

	for canonical, override := range snap.RuleOverrides {
		source, id, err := ParseCanonicalRuleID(canonical)
		if err != nil {
			add("RuleOverride", canonical, "canonical_id", err.Error())
			continue
		}
		if override == nil {
			continue
		}
		if !IsValidRuleAction(override.Action) {
			add("RuleOverride", canonical, "action", fmt.Sprintf("unknown action %q", override.Action))
		}
		if !IsValidSeverity(override.Severity) {
			add("RuleOverride", canonical, "severity", fmt.Sprintf("unknown severity %q", override.Severity))
		}
		if source == RuleSourceSemantic && !waf.IsValidModule(waf.Module(id)) {
			add("RuleOverride", canonical, "id", fmt.Sprintf("unknown semantic module %q", id))
		}
	}

	validatePolicy := func(entity, id string, policy *WAFPolicySnapshot) {
		if policy == nil {
			return
		}
		if policy.DetectionMode != "" && !IsValidDetectionMode(policy.DetectionMode) {
			add(entity, id, "detection_mode", fmt.Sprintf("unknown detection mode %q", policy.DetectionMode))
		}
		if policy.Sensitivity != "" && !IsValidSensitivity(policy.Sensitivity) {
			add(entity, id, "sensitivity", fmt.Sprintf("unknown sensitivity %q", policy.Sensitivity))
		}
		if policy.CRSParanoiaLevel != 0 && (policy.CRSParanoiaLevel < 1 || policy.CRSParanoiaLevel > 4) {
			add(entity, id, "crs_paranoia_level", "paranoia level must be between 1 and 4")
		}
		if policy.CRSInboundThreshold < 0 {
			add(entity, id, "crs_inbound_threshold", "inbound threshold cannot be negative")
		}
		if policy.CRSOutboundThreshold < 0 {
			add(entity, id, "crs_outbound_threshold", "outbound threshold cannot be negative")
		}
		for module, mode := range policy.SemanticOverrides {
			if !waf.IsValidModule(module) {
				add(entity, id, "semantic_overrides", fmt.Sprintf("unknown semantic module %q", module))
				continue
			}
			if mode > waf.ModeStrict {
				add(entity, id, "semantic_overrides", fmt.Sprintf("mode %d out of range for %q", uint8(mode), module))
			}
		}
		for _, packID := range policy.DisabledPacks {
			if _, exists := packIDs[packID]; !exists {
				add(entity, id, "disabled_packs", fmt.Sprintf("unknown pack %q", packID))
			}
		}
	}

	validatePolicy("WAFPolicy", "global", snap.WAFPolicy)
	for appID, app := range snap.Apps {
		if app != nil {
			validatePolicy("WAFPolicy", appID, app.WAFPolicy)
		}
	}

	return errs
}

func hasConfFile(files map[string]string) bool {
	for name := range files {
		if strings.HasSuffix(strings.ToLower(name), ".conf") {
			return true
		}
	}
	return false
}

// validateCorazaRuleset compiles enabled ModSecurity/CRS packs, attributing a
// failure to the offending pack when possible. Native packs are excluded.
func validateCorazaRuleset(packs []*RulePackSnapshot) error {
	conf := crs.Config{
		Mode:          crs.ModeAudit,
		MaxBodySize:   crs.DefaultMaxBodySize,
		ParanoiaLevel: crs.DefaultParanoiaLevel,
	}
	included := 0
	for _, pack := range packs {
		if pack == nil || !pack.Enabled || pack.Type == PackTypeNative {
			continue
		}
		included++
		conf.Packs = append(conf.Packs, crs.Pack{
			ID:             pack.ID,
			ReplaceBuiltin: pack.ReplaceBuiltin,
			Directives:     pack.Directives,
			Files:          pack.Files,
		})
	}
	if included == 0 {
		return nil
	}
	if _, err := crs.New(conf); err == nil {
		return nil
	} else {
		combinedErr := err
		for _, pack := range packs {
			if pack == nil || !pack.Enabled || pack.Type == PackTypeNative {
				continue
			}
			single := crs.Config{
				Mode:          crs.ModeAudit,
				MaxBodySize:   crs.DefaultMaxBodySize,
				ParanoiaLevel: crs.DefaultParanoiaLevel,
				Packs: []crs.Pack{{
					ID:             pack.ID,
					ReplaceBuiltin: pack.ReplaceBuiltin,
					Directives:     pack.Directives,
					Files:          pack.Files,
				}},
			}
			if _, err := crs.New(single); err != nil {
				return fmt.Errorf("pack %q: %w", pack.ID, err)
			}
		}
		return combinedErr
	}
}

func rulePackSize(pack *RulePackSnapshot) int {
	size := len(pack.Directives)
	for _, content := range pack.Files {
		size += len(content)
	}
	for _, rule := range pack.Rules {
		size += len(rule.ID) + len(rule.Name) + len(rule.Category) + len(rule.Prefix) + 64
	}
	return size
}
