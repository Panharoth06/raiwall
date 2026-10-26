package declarative

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// syncRatePolicies materializes per-host tiered rate limiting policies.
func (s *syncer) syncRatePolicies(policies []config.RatePolicy) error {
	existing, err := s.store.ListRatePolicies(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.RatePolicy, len(existing))
	byHost := make(map[string]control.RatePolicy, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byHost[strings.ToLower(rec.Host)] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		id := namedID(KindRatePolicy, policy.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byHost[strings.ToLower(policy.Host)]; taken && !IsManaged(other.ID) {
				if err := s.conflict("rate policy host "+policy.Host, policy.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		paths, _ := json.Marshal(policy.WaitingRoomPaths)
		now := time.Now().UTC()
		rec := control.RatePolicy{
			ID:                  id,
			Name:                policy.Name,
			Host:                policy.Host,
			Tier1Rate:           policy.Tier1Rate,
			Tier1Burst:          policy.Tier1Burst,
			Tier1PeriodSec:      seconds(policy.Tier1Period),
			Tier2Threshold:      policy.Tier2Threshold,
			Tier2PeriodSec:      seconds(policy.Tier2Window),
			Tier2BanDurationSec: seconds(policy.Tier2BanDuration),
			Tier3Threshold:      policy.Tier3Threshold,
			Tier3BanDurationSec: seconds(policy.Tier3BanDuration),
			WaitingRoomEnabled:  boolToInt(policy.WaitingRoomEnabled),
			WaitingRoomCapacity: policy.WaitingRoomCapacity,
			WaitingRoomPaths:    string(paths),
			IsActive:            1,
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if sameRatePolicy(prev, rec) {
				continue
			}
			if err := s.store.UpdateRatePolicy(s.ctx, rec); err != nil {
				if ferr := s.handle("rate policy", policy.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Updated++
			continue
		}
		if err := s.store.CreateRatePolicy(s.ctx, rec); err != nil {
			if ferr := s.handle("rate policy", policy.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		s.result.Created++
	}

	return s.pruneIDs(KindRatePolicy, declared, ids, func(id string) error {
		return s.store.DeleteRatePolicy(s.ctx, id)
	})
}

// syncBotPolicies materializes per-host bot mitigation overrides.
func (s *syncer) syncBotPolicies(policies []config.BotPolicy) error {
	existing, err := s.store.ListBotConfigs(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.BotConfig, len(existing))
	byHost := make(map[string]control.BotConfig, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byHost[strings.ToLower(rec.Host)] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		id := namedID(KindBotPolicy, policy.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byHost[strings.ToLower(policy.Host)]; taken && !IsManaged(other.ID) {
				if err := s.conflict("bot policy host "+policy.Host, policy.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		traps, _ := json.Marshal(policy.TrapURLs)
		difficulty := policy.PoWDifficulty
		if difficulty == 0 {
			difficulty = bot.DefaultPoWDifficulty
		}
		now := time.Now().UTC()
		rec := control.BotConfig{
			ID:            id,
			Host:          policy.Host,
			PowEnabled:    boolToInt(policy.PoWEnabled),
			PowDifficulty: difficulty,
			TrapUrls:      string(traps),
			IsActive:      1,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if sameBotPolicy(prev, rec) {
				continue
			}
			if err := s.store.UpdateBotConfig(s.ctx, rec); err != nil {
				if ferr := s.handle("bot policy", policy.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Updated++
			continue
		}
		if err := s.store.CreateBotConfig(s.ctx, rec); err != nil {
			if ferr := s.handle("bot policy", policy.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		s.result.Created++
	}

	return s.pruneIDs(KindBotPolicy, declared, ids, func(id string) error {
		return s.store.DeleteBotConfig(s.ctx, id)
	})
}

// syncIdentityProviders materializes OIDC/LDAP/GitHub connectors.
func (s *syncer) syncIdentityProviders(providers []config.IdentityProvider) error {
	existing, err := s.store.ListIdentityProviders(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.IdentityProviderRecord, len(existing))
	byName := make(map[string]control.IdentityProviderRecord, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byName[rec.Name] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		id := namedID(KindIdentityProvider, provider.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byName[provider.Name]; taken && !IsManaged(other.ID) {
				if err := s.conflict("identity provider", provider.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		cfg, err := json.Marshal(provider.Config)
		if err != nil {
			if ferr := s.handle("identity provider", provider.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		now := time.Now().UTC()
		rec := control.IdentityProviderRecord{
			ID:        id,
			Type:      strings.ToLower(provider.Type),
			Name:      provider.Name,
			Config:    string(cfg),
			Enabled:   boolToInt(enabled(provider.Enabled)),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if prev.Type == rec.Type && prev.Config == rec.Config && prev.Enabled == rec.Enabled {
				continue
			}
			s.result.Updated++
		} else {
			s.result.Created++
		}
		if err := s.store.UpsertIdentityProvider(s.ctx, rec); err != nil {
			if ferr := s.handle("identity provider", provider.Name, err); ferr != nil {
				return ferr
			}
		}
	}

	return s.pruneIDs(KindIdentityProvider, declared, ids, func(id string) error {
		return s.store.DeleteIdentityProvider(s.ctx, id)
	})
}

// syncTemplates materializes deterministic response pages keyed by status code.
func (s *syncer) syncTemplates(templates []config.Template) error {
	existing, err := s.store.ListTemplates(s.ctx)
	if err != nil {
		return err
	}
	byStatus := make(map[int]control.TemplateRecord, len(existing))
	managedStatuses := make(map[int]struct{}, len(existing))
	for _, rec := range existing {
		byStatus[rec.StatusCode] = rec
		if IsManaged(rec.ID) {
			managedStatuses[rec.StatusCode] = struct{}{}
		}
	}

	declared := make(map[string]struct{}, len(templates))
	declaredStatuses := make(map[int]struct{}, len(templates))
	for _, tmpl := range templates {
		id := namedID(KindTemplate, fmt.Sprintf("%d", tmpl.StatusCode))
		declared[id] = struct{}{}
		declaredStatuses[tmpl.StatusCode] = struct{}{}

		prev, exists := byStatus[tmpl.StatusCode]
		if exists && !IsManaged(prev.ID) {
			if err := s.conflict("response template", fmt.Sprintf("%d", tmpl.StatusCode)); err != nil {
				return err
			}
			continue
		}
		if exists && !s.canWrite(true) {
			continue
		}

		now := time.Now().UTC()
		rec := control.TemplateRecord{
			ID:          id,
			StatusCode:  tmpl.StatusCode,
			Title:       tmpl.Title,
			ContentHTML: tmpl.ContentHTML,
			CustomCSS:   tmpl.CustomCSS,
			BrandName:   tmpl.BrandName,
			LogoURL:     tmpl.LogoURL,
			IsCustom:    1,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if exists && prev.ID == id && prev.Title == rec.Title && prev.ContentHTML == rec.ContentHTML &&
			prev.CustomCSS == rec.CustomCSS && prev.BrandName == rec.BrandName && prev.LogoURL == rec.LogoURL {
			continue
		}
		if exists {
			if err := s.store.DeleteTemplate(s.ctx, tmpl.StatusCode); err != nil {
				if ferr := s.handle("response template", fmt.Sprintf("%d", tmpl.StatusCode), err); ferr != nil {
					return ferr
				}
				continue
			}
			if !prev.CreatedAt.IsZero() {
				rec.CreatedAt = prev.CreatedAt
			}
			s.result.Updated++
		} else {
			s.result.Created++
		}
		if err := s.store.UpsertTemplate(s.ctx, rec); err != nil {
			if ferr := s.handle("response template", fmt.Sprintf("%d", tmpl.StatusCode), err); ferr != nil {
				return ferr
			}
		}
	}

	if !s.prune {
		return nil
	}
	for status := range managedStatuses {
		if _, keep := declaredStatuses[status]; keep {
			continue
		}
		if err := s.store.DeleteTemplate(s.ctx, status); err != nil {
			return err
		}
		s.result.Deleted++
	}
	return nil
}

// syncDetector applies semantic module modes and virtual-patch toggles.
func (s *syncer) syncDetector(detector *config.Detector) error {
	if detector == nil {
		return nil
	}

	for name, mode := range detector.Modules {
		module := waf.Module(name)
		if !waf.IsValidModule(module) {
			if err := s.handle("detector module", name, fmt.Errorf("unknown semantic module")); err != nil {
				return err
			}
			continue
		}
		parsed, err := waf.ParseModuleModeString(mode)
		if err != nil {
			if ferr := s.handle("detector module", name, err); ferr != nil {
				return ferr
			}
			continue
		}
		if err := s.store.UpsertDetectorConfig(s.ctx, control.DetectorConfigRecord{
			Module:    name,
			Mode:      parsed.String(),
			UpdatedAt: time.Now().UTC(),
		}); err != nil {
			if ferr := s.handle("detector module", name, err); ferr != nil {
				return ferr
			}
		}
	}

	// In sync mode the file is authoritative for the disabled-rule set.
	if s.mode == "sync" {
		if err := s.store.ClearDisabledInnerRules(s.ctx); err != nil {
			return err
		}
	}
	for _, ruleID := range detector.InnerRulesDisabled {
		clean := strings.TrimSpace(ruleID)
		if clean == "" {
			continue
		}
		if err := s.store.SetInnerRuleDisabled(s.ctx, clean, true); err != nil {
			if ferr := s.handle("inner rule", clean, err); ferr != nil {
				return ferr
			}
		}
	}
	return nil
}

func seconds(d config.Duration) int64 {
	return int64(d.Std() / time.Second)
}

func sameRatePolicy(a, b control.RatePolicy) bool {
	return a.Name == b.Name && a.Host == b.Host && a.Tier1Rate == b.Tier1Rate &&
		a.Tier1Burst == b.Tier1Burst && a.Tier1PeriodSec == b.Tier1PeriodSec &&
		a.Tier2Threshold == b.Tier2Threshold && a.Tier2PeriodSec == b.Tier2PeriodSec &&
		a.Tier2BanDurationSec == b.Tier2BanDurationSec && a.Tier3Threshold == b.Tier3Threshold &&
		a.Tier3BanDurationSec == b.Tier3BanDurationSec && a.WaitingRoomEnabled == b.WaitingRoomEnabled &&
		a.WaitingRoomCapacity == b.WaitingRoomCapacity && a.WaitingRoomPaths == b.WaitingRoomPaths &&
		a.IsActive == b.IsActive
}

func sameBotPolicy(a, b control.BotConfig) bool {
	return a.Host == b.Host && a.PowEnabled == b.PowEnabled &&
		a.PowDifficulty == b.PowDifficulty && a.TrapUrls == b.TrapUrls && a.IsActive == b.IsActive
}
