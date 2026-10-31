package control

import (
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

func nativePackCatalogItem(pack *RulePackSnapshot, rule cve.Signature, canonical string) RuleCatalogItem {
	item := RuleCatalogItem{
		ID:              canonical,
		Source:          RuleSourcePack,
		PackID:          pack.ID,
		PackName:        pack.Name,
		Name:            rule.Name,
		Category:        rule.Category,
		Severity:        SeverityForCategory(rule.Category),
		DefaultSeverity: SeverityForCategory(rule.Category),
		Action:          RuleActionBlock,
		DefaultAction:   RuleActionBlock,
		Enabled:         pack.Enabled,
		Methods:         append([]string(nil), rule.Methods...),
		Prefix:          rule.Prefix,
	}
	if !pack.Enabled {
		item.Action = RuleActionOff
	}
	return item
}

func modsecPackCatalogItem(pack *RulePackSnapshot, meta crs.RuleMeta, canonical string) RuleCatalogItem {
	item := RuleCatalogItem{
		ID:              canonical,
		Source:          RuleSourcePack,
		PackID:          pack.ID,
		PackName:        pack.Name,
		Name:            meta.Message,
		Category:        firstUsefulTag(meta.Tags, "modsec"),
		Severity:        normalizeRuleSeverity(meta.Severity),
		DefaultSeverity: normalizeRuleSeverity(meta.Severity),
		Action:          RuleActionBlock,
		DefaultAction:   RuleActionBlock,
		Enabled:         pack.Enabled,
		Phase:           meta.Phase,
	}
	if !pack.Enabled {
		item.Action = RuleActionOff
	}
	return item
}

func scanModsecPackMetadata(pack *RulePackSnapshot) []crs.RuleMeta {
	metadata := crs.ScanDirectiveMetadata(pack.Directives)
	for name, content := range pack.Files {
		if strings.HasSuffix(strings.ToLower(name), ".conf") {
			metadata = append(metadata, crs.ScanDirectiveMetadata(content)...)
		}
	}
	return metadata
}

func firstUsefulTag(tags []string, fallback string) string {
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if lower == "owasp_crs" ||
			strings.HasPrefix(lower, "paranoia-level/") ||
			strings.HasPrefix(lower, "capec/") {
			continue
		}
		return tag
	}
	return fallback
}

func normalizeRuleSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return SeverityMedium
	}
}

func newCVECatalogItem(rule cve.Signature) RuleCatalogItem {
	return RuleCatalogItem{
		ID:              CanonicalRuleID(RuleSourceCVE, rule.ID),
		Source:          RuleSourceCVE,
		PackID:          "cve-bundled",
		PackName:        "Raiwall Core CVE Virtual Patches",
		Name:            rule.Name,
		Category:        rule.Category,
		Severity:        SeverityForCategory(rule.Category),
		DefaultSeverity: SeverityForCategory(rule.Category),
		Action:          RuleActionBlock,
		DefaultAction:   RuleActionBlock,
		Enabled:         true,
		Methods:         append([]string(nil), rule.Methods...),
		Prefix:          rule.Prefix,
	}
}

func applyCatalogOverride(item *RuleCatalogItem, override *RuleOverrideSnapshot) {
	if item == nil || override == nil {
		return
	}
	item.Overridden = true
	if override.Enabled != nil {
		item.Enabled = *override.Enabled
		if !*override.Enabled {
			item.Action = RuleActionOff
		}
	}
	if action := NormalizePolicyValue(override.Action); action != "" {
		item.Action = action
		item.Enabled = action != RuleActionOff
	}
	if override.Severity != "" {
		item.Severity = override.Severity
	}
}

func actionForModuleMode(mode waf.ModuleMode) string {
	switch mode {
	case waf.ModeDisabled:
		return RuleActionOff
	case waf.ModeAudit:
		return RuleActionAlert
	default:
		return RuleActionBlock
	}
}

func severityForSemanticCategory(category string) string {
	switch strings.ToLower(category) {
	case "injection", "file":
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

// SeverityForCategory maps an attack category to the catalog severity scale.
func SeverityForCategory(category string) string {
	switch strings.ToLower(category) {
	case "rce", "deserialization", "cve":
		return SeverityCritical
	case "auth-bypass", "injection", "upload", "ssrf", "file-inclusion":
		return SeverityHigh
	case "xss", "traversal", "info-disclosure":
		return SeverityMedium
	case "dos":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func sourceOrder(source string) int {
	switch source {
	case RuleSourceSemantic:
		return 0
	case RuleSourceCVE:
		return 1
	case RuleSourceCRS:
		return 2
	default:
		return 3
	}
}
