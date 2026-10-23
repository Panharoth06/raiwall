package control

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// CompileSnapshot queries relational configuration entities and compiles
// an immutable, validated ConfigSnapshot.
func CompileSnapshot(ctx context.Context, store ControlStore) (*ConfigSnapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}

	// 1. Load Apps
	dbApps, err := store.ListApps(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load apps: %w", err)
	}

	forwardingRulesByApp := make(map[string][]ForwardingRule)
	if dbRules, err := store.ListAllActiveForwardingRules(ctx); err == nil {
		for _, r := range dbRules {
			var upstreams []UpstreamTarget
			if r.Upstreams != "" {
				_ = json.Unmarshal([]byte(r.Upstreams), &upstreams)
			}
			forwardingRulesByApp[r.AppID] = append(forwardingRulesByApp[r.AppID], ForwardingRule{
				ID:                 r.ID,
				AppID:              r.AppID,
				Prefix:             r.Prefix,
				Upstreams:          upstreams,
				StripPrefix:        r.StripPrefix == 1,
				HostHeaderOverride: r.HostHeaderOverride,
				Comment:            r.Comment,
				IsActive:           r.IsActive == 1,
			})
		}
	}

	appConfigs := make([]*AppConfig, 0, len(dbApps))
	for _, a := range dbApps {
		var hostnames []string
		if a.Hostnames != "" {
			_ = json.Unmarshal([]byte(a.Hostnames), &hostnames)
		}
		var upstreams []UpstreamTarget
		if a.Upstreams != "" {
			_ = json.Unmarshal([]byte(a.Upstreams), &upstreams)
		}
		var customHeaders map[string]string
		if a.CustomHeaders != "" {
			_ = json.Unmarshal([]byte(a.CustomHeaders), &customHeaders)
		}
		var proxySettings *ProxySettings
		if a.ProxySettings != "" {
			var ps ProxySettings
			if err := json.Unmarshal([]byte(a.ProxySettings), &ps); err == nil {
				proxySettings = &ps
			}
		}

		appConfigs = append(appConfigs, &AppConfig{
			ID:                  a.ID,
			Name:                a.Name,
			Hostnames:           hostnames,
			Mode:                RunMode(a.Mode),
			Upstreams:           upstreams,
			ForwardingRules:     forwardingRulesByApp[a.ID],
			ProxySettings:       proxySettings,
			BlockStatusCode:     int(a.BlockStatusCode),
			BlockResponseBody:   a.BlockResponseBody,
			OfflineStatusCode:   int(a.OfflineStatusCode),
			OfflineResponseBody: a.OfflineResponseBody,
			CustomHeaders:       customHeaders,
		})
	}

	// 2. Load Active Exceptions
	dbExceptions, err := store.ListActiveExceptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load exceptions: %w", err)
	}
	exceptions := make([]*acl.ExceptionRule, 0, len(dbExceptions))
	for _, e := range dbExceptions {
		exc := &acl.ExceptionRule{
			ID:          e.ID,
			Description: e.Description,
			Host:        e.Host,
			PathRegex:   e.PathRegex,
			PathPrefix:  e.PathPrefix,
			Method:      e.Method,
			Location:    e.Location,
			ParamName:   e.ParamName,
			ParamRegex:  e.ParamRegex,
			RuleID:      e.RuleID,
		}
		exceptions = append(exceptions, exc)
	}

	// 3. Load Active ACL Rules
	dbAcls, err := store.ListActiveACLRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load acl rules: %w", err)
	}
	aclRules := make([]*acl.ACLRule, 0, len(dbAcls))
	for _, r := range dbAcls {
		rule := &acl.ACLRule{
			Name:        r.Name,
			Expression:  r.Expression,
			Action:      acl.Action(r.Action),
			Priority:    int(r.Priority),
			StatusCode:  int(r.StatusCode),
			RedirectURL: r.RedirectUrl,
		}
		aclRules = append(aclRules, rule)
	}

	// 4. Load Active Rate Policies
	dbRatePolicies, err := store.ListActiveRatePolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load rate policies: %w", err)
	}
	ratePolicies := make([]*RatePolicySnapshot, 0, len(dbRatePolicies))
	for _, rp := range dbRatePolicies {
		var waitingRoomPaths []string
		if rp.WaitingRoomPaths != "" {
			_ = json.Unmarshal([]byte(rp.WaitingRoomPaths), &waitingRoomPaths)
		}

		pol := &RatePolicySnapshot{
			ID:                  rp.ID,
			Name:                rp.Name,
			Host:                rp.Host,
			Tier1Rate:           rp.Tier1Rate,
			Tier1Burst:          rp.Tier1Burst,
			Tier1Period:         time.Duration(rp.Tier1PeriodSec) * time.Second,
			Tier2Threshold:      rp.Tier2Threshold,
			Tier2Period:         time.Duration(rp.Tier2PeriodSec) * time.Second,
			Tier2BanDuration:    time.Duration(rp.Tier2BanDurationSec) * time.Second,
			Tier3Threshold:      rp.Tier3Threshold,
			Tier3BanDuration:    time.Duration(rp.Tier3BanDurationSec) * time.Second,
			WaitingRoomEnabled:  rp.WaitingRoomEnabled == 1,
			WaitingRoomCapacity: rp.WaitingRoomCapacity,
			WaitingRoomPaths:    waitingRoomPaths,
		}
		ratePolicies = append(ratePolicies, pol)
	}

	// 5. Load Active Bot Configs
	dbBotConfigs, err := store.ListActiveBotConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load bot configs: %w", err)
	}
	botConfigs := make([]*BotConfigSnapshot, 0, len(dbBotConfigs))
	for _, bc := range dbBotConfigs {
		var traps []string
		if bc.TrapUrls != "" {
			_ = json.Unmarshal([]byte(bc.TrapUrls), &traps)
		}
		botConfigs = append(botConfigs, &BotConfigSnapshot{
			ID:            bc.ID,
			Host:          bc.Host,
			PowEnabled:    bc.PowEnabled == 1,
			PowDifficulty: int(bc.PowDifficulty),
			TrapURLs:      traps,
		})
	}

	// 6. Load Semantic Detector Matrix (global defaults + per-app overrides)
	dbDetectorConfig, err := store.ListDetectorConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load detector config: %w", err)
	}
	semanticDefaults := make(map[waf.Module]waf.ModuleMode, len(dbDetectorConfig))
	for _, cfg := range dbDetectorConfig {
		detector := waf.Module(cfg.Module)
		if !waf.IsValidModule(detector) {
			return nil, fmt.Errorf("unknown semantic module %q in detector config", cfg.Module)
		}
		mode, modeErr := waf.ParseModuleModeString(cfg.Mode)
		if modeErr != nil {
			return nil, fmt.Errorf("invalid mode %q for semantic module %q: %w", cfg.Mode, cfg.Module, modeErr)
		}
		semanticDefaults[detector] = mode
	}

	dbAppPolicies, err := store.ListAppSemanticPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load app semantic policies: %w", err)
	}
	appSemOverrides := make(map[string]map[waf.Module]waf.ModuleMode, len(dbAppPolicies))
	for _, rec := range dbAppPolicies {
		var overrides map[waf.Module]waf.ModuleMode
		if rec.Policy != "" {
			if err := json.Unmarshal([]byte(rec.Policy), &overrides); err != nil {
				return nil, fmt.Errorf("invalid semantic policy JSON for app %q: %w", rec.AppID, err)
			}
		}
		for module := range overrides {
			if !waf.IsValidModule(module) {
				return nil, fmt.Errorf("unknown semantic module %q in policy for app %q", module, rec.AppID)
			}
		}
		appSemOverrides[rec.AppID] = overrides
	}

	// Determine next version or initial version 1
	var version uint64 = 1
	latest, err := store.GetLatestSnapshot(ctx)
	if err == nil && latest.Version > 0 {
		version = uint64(latest.Version + 1)
	}

	snap := NewConfigSnapshot(version, ModeDefense, appConfigs)
	snap.Exceptions = exceptions
	snap.ACLRules = aclRules
	snap.RatePolicies = ratePolicies
	snap.BotConfigs = botConfigs
	snap.SemanticDefaults = semanticDefaults

	// Join per-app semantic overrides (matrix step runs after apps are registered).
	for appID, overrides := range appSemOverrides {
		if app, ok := snap.Apps[appID]; ok && app != nil {
			app.SemanticPolicy = overrides
		}
	}

	// Run pre-flight validation
	if err := ValidateSnapshot(snap); err != nil {
		return nil, err
	}

	return snap, nil
}
