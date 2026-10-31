package control

import (
	"sort"
	"strconv"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

// RuleCatalogItem is one detection unit shown in the operator rule catalog.
type RuleCatalogItem struct {
	ID              string   `json:"id"` // canonical source:id
	Source          string   `json:"source"`
	PackID          string   `json:"pack_id,omitempty"`
	PackName        string   `json:"pack_name,omitempty"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	DefaultSeverity string   `json:"default_severity"`
	Action          string   `json:"action"`
	DefaultAction   string   `json:"default_action"`
	Enabled         bool     `json:"enabled"`
	Overridden      bool     `json:"overridden"`
	Phase           int      `json:"phase,omitempty"`
	Methods         []string `json:"methods,omitempty"`
	Prefix          string   `json:"prefix,omitempty"`
	Description     string   `json:"description,omitempty"`
}

// BuildRuleCatalog merges semantic modules, bundled CVE patches, embedded CRS
// rules, and imported packs into one catalog with effective overrides applied.
func BuildRuleCatalog(snap *ConfigSnapshot) []RuleCatalogItem {
	items := make([]RuleCatalogItem, 0, len(waf.ModuleRegistry)+128)

	matrix := waf.DefaultMatrix()
	if snap != nil {
		matrix = snap.SemanticMatrixFor("")
	}
	for _, meta := range waf.ModuleRegistry {
		mode := matrix.Mode(meta.Module)
		action := actionForModuleMode(mode)
		item := RuleCatalogItem{
			ID:              CanonicalRuleID(RuleSourceSemantic, string(meta.Module)),
			Source:          RuleSourceSemantic,
			Name:            meta.Name,
			Category:        meta.Category,
			Severity:        severityForSemanticCategory(meta.Category),
			DefaultSeverity: severityForSemanticCategory(meta.Category),
			Action:          action,
			DefaultAction:   RuleActionBlock,
			Enabled:         mode != waf.ModeDisabled,
			Description:     meta.Description,
		}
		if snap != nil {
			if _, ok := snap.SemanticDefaults[meta.Module]; ok {
				item.Overridden = true
			}
			if override := snap.RuleOverrides[item.ID]; override != nil && override.Severity != "" {
				item.Severity = override.Severity
				item.Overridden = true
			}
		}
		items = append(items, item)
	}

	if rules, err := cve.BundledRules(); err == nil {
		for _, rule := range rules {
			item := newCVECatalogItem(rule)
			if snap != nil {
				if _, disabled := snap.InnerRulesDisabled[rule.ID]; disabled {
					item.Action = RuleActionOff
					item.Enabled = false
					item.Overridden = true
				}
				applyCatalogOverride(&item, snap.RuleOverrides[item.ID])
			}
			items = append(items, item)
		}
	}

	if metadata, err := crs.EmbeddedRuleMetadata(); err == nil {
		for _, meta := range metadata {
			item := RuleCatalogItem{
				ID:              CanonicalRuleID(RuleSourceCRS, strconv.Itoa(meta.ID)),
				Source:          RuleSourceCRS,
				PackID:          "crs-embedded",
				PackName:        "OWASP CRS 4.x (embedded)",
				Name:            meta.Message,
				Category:        firstUsefulTag(meta.Tags, "crs"),
				Severity:        normalizeRuleSeverity(meta.Severity),
				DefaultSeverity: normalizeRuleSeverity(meta.Severity),
				Action:          RuleActionBlock,
				DefaultAction:   RuleActionBlock,
				Enabled:         true,
				Phase:           meta.Phase,
			}
			if snap != nil {
				applyCatalogOverride(&item, snap.RuleOverrides[item.ID])
			}
			items = append(items, item)
		}
	}

	if snap != nil {
		for _, pack := range snap.RulePacks {
			if pack == nil {
				continue
			}
			if pack.Type == PackTypeNative {
				for _, rule := range pack.Rules {
					canonical := CanonicalRuleID(RuleSourcePack, pack.ID+":"+rule.ID)
					item := nativePackCatalogItem(pack, rule, canonical)
					applyCatalogOverride(&item, snap.RuleOverrides[canonical])
					items = append(items, item)
				}
				continue
			}
			for _, meta := range scanModsecPackMetadata(pack) {
				canonical := CanonicalRuleID(RuleSourcePack, pack.ID+":"+strconv.Itoa(meta.ID))
				item := modsecPackCatalogItem(pack, meta, canonical)
				applyCatalogOverride(&item, snap.RuleOverrides[canonical])
				items = append(items, item)
			}
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Source != items[j].Source {
			return sourceOrder(items[i].Source) < sourceOrder(items[j].Source)
		}
		if items[i].Category != items[j].Category {
			return items[i].Category < items[j].Category
		}
		return items[i].ID < items[j].ID
	})
	return items
}
