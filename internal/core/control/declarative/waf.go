package declarative

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// Additional declarative resource kinds for detection configuration.
const (
	KindRulePack  = "rule_pack"
	KindWAFPolicy = "waf_policy"
)

// syncWAFConfig applies detection policy, per-rule overrides, and imported
// packs. Modules and legacy inner-rule toggles are handled by syncDetector.
func (s *syncer) syncWAFConfig(detector *config.Detector) error {
	if detector == nil {
		return nil
	}
	if err := s.syncRulePacks(detector.RulePacks); err != nil {
		return err
	}
	if err := s.syncRuleOverrides(detector.RuleOverrides); err != nil {
		return err
	}
	if err := s.syncWAFPolicy(detector.Policy); err != nil {
		return err
	}
	return s.syncAppWAFPolicies(detector.AppPolicies)
}

func (s *syncer) syncRulePacks(packs []config.RulePack) error {
	existing, err := s.store.ListRulePacks(s.ctx)
	if err != nil {
		return err
	}
	byNameVersion := make(map[string]control.RulePackRecord, len(existing))
	for _, pack := range existing {
		byNameVersion[pack.Name+"\x00"+pack.Version] = pack
	}
	declared := make(map[string]struct{}, len(packs))

	for _, pack := range packs {
		name := strings.TrimSpace(pack.Name)
		version := strings.TrimSpace(pack.Version)
		if version == "" {
			version = "1.0.0"
		}
		packType := strings.ToLower(strings.TrimSpace(pack.Type))
		if packType == "" {
			packType = control.PackTypeNative
		}
		relation := strings.ToLower(strings.TrimSpace(pack.Relation))
		if relation == "" {
			relation = control.PackRelationAdditive
		}

		record, exists := byNameVersion[name+"\x00"+version]
		if exists && !IsManaged(record.ID) {
			s.result.Warnings = append(s.result.Warnings,
				fmt.Sprintf("rule pack %q version %q is API-managed; declarative entry skipped", name, version))
			continue
		}
		if !exists {
			record = control.RulePackRecord{
				ID: namedID(KindRulePack, name+"@"+version),
			}
		}
		if _, overridden := s.overrides[record.ID]; overridden {
			continue
		}

		rulesJSON := "[]"
		filesJSON := "{}"
		directives := ""
		if packType == control.PackTypeNative {
			encoded, err := json.Marshal(pack.Rules)
			if err != nil {
				if ferr := s.handle("rule pack", name, err); ferr != nil {
					return ferr
				}
				continue
			}
			rulesJSON = string(encoded)
		} else {
			directives = pack.Directives
			encoded, err := json.Marshal(pack.Files)
			if err != nil {
				if ferr := s.handle("rule pack", name, err); ferr != nil {
					return ferr
				}
				continue
			}
			filesJSON = string(encoded)
		}

		record.Name = name
		record.Version = version
		record.Type = packType
		record.Priority = pack.Priority
		if record.Priority <= 0 {
			record.Priority = 100
		}
		record.Enabled = true
		record.ReplaceBuiltin = relation == control.PackRelationReplace
		record.RulesJSON = rulesJSON
		record.Directives = directives
		record.FilesJSON = filesJSON
		record.Checksum = packChecksum(record)
		record.UpdatedAt = time.Now().UTC()

		if err := s.store.UpsertRulePack(s.ctx, record); err != nil {
			if ferr := s.handle("rule pack", name, err); ferr != nil {
				return ferr
			}
			continue
		}
		declared[record.ID] = struct{}{}
		if exists {
			s.result.Updated++
		} else {
			s.result.Created++
		}
	}

	if !s.prune {
		return nil
	}
	for _, pack := range existing {
		if !IsManaged(pack.ID) {
			continue
		}
		if _, keep := declared[pack.ID]; keep {
			continue
		}
		if _, overridden := s.overrides[pack.ID]; overridden {
			continue
		}
		if err := s.store.DeleteRulePack(s.ctx, pack.ID); err != nil {
			return err
		}
		s.result.Deleted++
	}
	return nil
}

func (s *syncer) syncRuleOverrides(overrides []config.RuleOverride) error {
	for _, override := range overrides {
		canonical, err := canonicalOverrideID(override)
		if err != nil {
			if ferr := s.handle("rule override", override.ID, err); ferr != nil {
				return ferr
			}
			continue
		}
		record := control.RuleOverrideRecord{
			CanonicalID: canonical,
			Enabled:     override.Enabled,
			Action:      normalizeAction(override.Action),
			Severity:    strings.ToLower(strings.TrimSpace(override.Severity)),
			UpdatedBy:   "declarative",
			UpdatedAt:   time.Now().UTC(),
		}
		if err := s.store.UpsertRuleOverride(s.ctx, record); err != nil {
			if ferr := s.handle("rule override", override.ID, err); ferr != nil {
				return ferr
			}
		}
	}
	return nil
}

func (s *syncer) syncWAFPolicy(policy *config.DetectorPolicy) error {
	if policy == nil {
		return nil
	}
	record := policyRecord("global", control.PolicyScopeGlobal, "", policy)
	if err := s.store.UpsertWAFPolicy(s.ctx, record); err != nil {
		return s.handle("waf policy", "global", err)
	}
	return nil
}

func (s *syncer) syncAppWAFPolicies(policies []config.AppDetectorPolicy) error {
	if len(policies) == 0 {
		return nil
	}
	apps, err := s.store.ListApps(s.ctx)
	if err != nil {
		return err
	}
	byName := make(map[string]control.SiteApp, len(apps))
	for _, app := range apps {
		byName[app.Name] = app
	}
	for _, entry := range policies {
		app, ok := byName[entry.App]
		if !ok {
			s.result.Warnings = append(s.result.Warnings,
				fmt.Sprintf("detector app policy references unknown application %q", entry.App))
			continue
		}
		record := policyRecord(namedID(KindWAFPolicy, entry.App), control.PolicyScopeApp, app.ID, &entry.Policy)
		if err := s.store.UpsertWAFPolicy(s.ctx, record); err != nil {
			if ferr := s.handle("app waf policy", entry.App, err); ferr != nil {
				return ferr
			}
		}
	}
	return nil
}

func policyRecord(id, scope, appID string, policy *config.DetectorPolicy) control.WAFPolicyRecord {
	semantic := policy.Semantic
	if semantic == nil {
		semantic = map[string]string{}
	}
	semanticJSON, _ := json.Marshal(semantic)
	packs := policy.DisabledPacks
	if packs == nil {
		packs = []string{}
	}
	packsJSON, _ := json.Marshal(packs)

	record := control.WAFPolicyRecord{
		ID:                id,
		Scope:             scope,
		AppID:             appID,
		DetectionMode:     normalizePolicyValue(policy.Mode),
		Sensitivity:       normalizePolicyValue(policy.Sensitivity),
		SemanticOverrides: string(semanticJSON),
		DisabledPackIDs:   string(packsJSON),
		UpdatedAt:         time.Now().UTC(),
	}
	if policy.CRS != nil {
		record.CRSEnabled = policy.CRS.Enabled
		if policy.CRS.ParanoiaLevel > 0 {
			pl := policy.CRS.ParanoiaLevel
			record.CRSParanoiaLevel = &pl
		}
		if policy.CRS.InboundThreshold > 0 {
			in := policy.CRS.InboundThreshold
			record.CRSInboundThreshold = &in
		}
		if policy.CRS.OutboundThreshold > 0 {
			out := policy.CRS.OutboundThreshold
			record.CRSOutboundThreshold = &out
		}
	}
	return record
}

func canonicalOverrideID(override config.RuleOverride) (string, error) {
	source := strings.ToLower(strings.TrimSpace(override.Source))
	id := strings.TrimSpace(override.ID)
	if id == "" {
		return "", fmt.Errorf("rule id is required")
	}
	if source == "" {
		switch {
		case waf.IsValidModule(waf.Module(id)):
			source = control.RuleSourceSemantic
		case strings.HasPrefix(strings.ToUpper(id), "CVE-"):
			source = control.RuleSourceCVE
		case isNumeric(id):
			source = control.RuleSourceCRS
		case strings.Contains(id, ":"):
			source = control.RuleSourcePack
		default:
			source = control.RuleSourceCVE
		}
	}
	if !control.IsValidRuleSource(source) {
		return "", fmt.Errorf("unknown rule source %q", source)
	}
	return control.CanonicalRuleID(source, id), nil
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizePolicyValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "inherit" {
		return ""
	}
	return value
}

func normalizeAction(value string) string {
	value = normalizePolicyValue(value)
	return value
}

func packChecksum(record control.RulePackRecord) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(record.RulesJSON))
	_, _ = hash.Write([]byte(record.Directives))
	_, _ = hash.Write([]byte(record.FilesJSON))
	return hex.EncodeToString(hash.Sum(nil))
}
