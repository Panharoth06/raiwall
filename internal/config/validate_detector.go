package config

import (
	"fmt"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// validateDetectorConfig checks semantic modules, detection policy, per-rule
// overrides, imported packs, and per-site policies.
func validateDetectorConfig(v *validator, detector *Detector) {
	if detector == nil {
		return
	}
	for module, mode := range detector.Modules {
		if !waf.IsValidModule(waf.Module(module)) {
			v.add("detector.modules.%s is not a known semantic module", module)
		}
		switch strings.ToLower(mode) {
		case "disabled", "audit", "balance", "strict":
		default:
			v.add("detector.modules.%s mode %q must be disabled, audit, balance, or strict", module, mode)
		}
	}
	validateDetectorPolicy(v, "detector.policy", detector.Policy)

	seenPacks := make(map[string]struct{}, len(detector.RulePacks))
	for i, pack := range detector.RulePacks {
		prefix := fmt.Sprintf("detector.rule_packs[%d]", i)
		if strings.TrimSpace(pack.Name) == "" {
			v.add("%s.name is required", prefix)
		}
		version := pack.Version
		if strings.TrimSpace(version) == "" {
			version = "1.0.0"
		}
		key := pack.Name + "\x00" + version
		if _, exists := seenPacks[key]; exists {
			v.add("%s duplicates pack %q version %q", prefix, pack.Name, version)
		}
		seenPacks[key] = struct{}{}
		packType := pack.Type
		if packType == "" {
			packType = "native"
		}
		switch packType {
		case "native", "modsec", "crs":
		default:
			v.add("%s.type %q must be native, modsec, or crs", prefix, pack.Type)
		}
		relation := pack.Relation
		if relation == "" {
			relation = "additive"
		}
		if relation != "additive" && relation != "replace" {
			v.add("%s.relation %q must be additive or replace", prefix, pack.Relation)
		}
		if relation == "replace" && packType != "crs" {
			v.add("%s.relation replace is only valid for crs packs", prefix)
		}
		switch packType {
		case "native":
			if len(pack.Rules) == 0 {
				v.add("%s.rules is required for native packs", prefix)
			}
		case "modsec", "crs":
			if strings.TrimSpace(pack.Directives) == "" && !hasConfFiles(pack.Files) {
				v.add("%s requires directives or at least one .conf file", prefix)
			}
		}
	}

	for i, override := range detector.RuleOverrides {
		prefix := fmt.Sprintf("detector.rule_overrides[%d]", i)
		if strings.TrimSpace(override.ID) == "" {
			v.add("%s.id is required", prefix)
		}
		switch strings.ToLower(strings.TrimSpace(override.Source)) {
		case "", "semantic", "cve", "crs", "pack":
		default:
			v.add("%s.source %q must be semantic, cve, crs, or pack", prefix, override.Source)
		}
		switch strings.ToLower(strings.TrimSpace(override.Action)) {
		case "", "inherit", "block", "alert", "off":
		default:
			v.add("%s.action %q must be inherit, block, alert, or off", prefix, override.Action)
		}
		switch strings.ToLower(strings.TrimSpace(override.Severity)) {
		case "", "low", "medium", "high", "critical":
		default:
			v.add("%s.severity %q must be low, medium, high, or critical", prefix, override.Severity)
		}
	}

	for i, appPolicy := range detector.AppPolicies {
		prefix := fmt.Sprintf("detector.app_policies[%d]", i)
		if strings.TrimSpace(appPolicy.App) == "" {
			v.add("%s.app is required", prefix)
		}
		validateDetectorPolicy(v, prefix+".policy", &appPolicy.Policy)
	}
}

func validateDetectorPolicy(v *validator, prefix string, policy *DetectorPolicy) {
	if policy == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(policy.Mode)) {
	case "", "inherit", "off", "alert", "block":
	default:
		v.add("%s.mode %q must be inherit, off, alert, or block", prefix, policy.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(policy.Sensitivity)) {
	case "", "inherit", "low", "medium", "high":
	default:
		v.add("%s.sensitivity %q must be inherit, low, medium, or high", prefix, policy.Sensitivity)
	}
	if policy.CRS != nil {
		if policy.CRS.ParanoiaLevel < 0 || policy.CRS.ParanoiaLevel > 4 {
			v.add("%s.crs.paranoia_level must be between 0 and 4", prefix)
		}
		if policy.CRS.InboundThreshold < 0 || policy.CRS.OutboundThreshold < 0 {
			v.add("%s.crs thresholds cannot be negative", prefix)
		}
	}
	if policy.Response != nil {
		switch strings.ToLower(strings.TrimSpace(policy.Response.Mode)) {
		case "", "inherit", "audit", "redact", "block":
		default:
			v.add("%s.response.mode %q must be inherit, audit, redact, or block", prefix, policy.Response.Mode)
		}
		if policy.Response.BodyLimit < 0 {
			v.add("%s.response.body_limit cannot be negative", prefix)
		}
		if policy.Response.HardCap < 0 {
			v.add("%s.response.hard_cap cannot be negative", prefix)
		}
		if policy.Response.MaxInflightBytes < 0 {
			v.add("%s.response.max_inflight_bytes cannot be negative", prefix)
		}
		if policy.Response.DLP != nil {
			switch strings.ToLower(strings.TrimSpace(policy.Response.DLP.Action)) {
			case "", "inherit", "audit", "redact", "block":
			default:
				v.add("%s.response.dlp.action %q must be inherit, audit, redact, or block", prefix, policy.Response.DLP.Action)
			}
			if policy.Response.DLP.MaxScanBytes < 0 {
				v.add("%s.response.dlp.max_scan_bytes cannot be negative", prefix)
			}
		}
	}
	for module, mode := range policy.Semantic {
		if !waf.IsValidModule(waf.Module(module)) {
			v.add("%s.semantic.%s is not a known semantic module", prefix, module)
		}
		if !waf.IsValidModuleMode(mode) {
			v.add("%s.semantic.%s mode %q must be disabled, audit, balance, or strict", prefix, module, mode)
		}
	}
}

func hasConfFiles(files map[string]string) bool {
	for name := range files {
		if strings.HasSuffix(strings.ToLower(name), ".conf") {
			return true
		}
	}
	return false
}
