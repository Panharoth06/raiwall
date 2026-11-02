package caddy

import (
	"sort"
	"sync/atomic"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"go.uber.org/zap"
)

// crsPolicySet is one immutable generation of compiled Coraza policies. Apps
// whose resolved policy and exception set are identical share an engine.
type crsPolicySet struct {
	global *crs.Engine
	byApp  map[string]*crs.Engine
}

// crsPolicyEngine selects the compiled policy for a request's application.
// Deploys build a new set and swap it atomically, so requests never observe a
// half-compiled policy.
type crsPolicyEngine struct {
	current atomic.Pointer[crsPolicySet]
}

func newCRSPolicyEngine() *crsPolicyEngine { return &crsPolicyEngine{} }

func (e *crsPolicyEngine) store(set *crsPolicySet) { e.current.Store(set) }

// Name returns the identifier for this engine.
func (e *crsPolicyEngine) Name() string { return "crs" }

// InspectRequest evaluates the policy resolved for the request's app, falling
// back to the global policy.
func (e *crsPolicyEngine) InspectRequest(ctx *waf.RequestContext) (*waf.Verdict, error) {
	set := e.current.Load()
	if set == nil || set.global == nil {
		return waf.VerdictAllow, nil
	}
	engine := set.global
	if ctx != nil && ctx.AppID != "" {
		if appEngine, ok := set.byApp[ctx.AppID]; ok {
			engine = appEngine
		}
	}
	return engine.InspectRequest(ctx)
}

// InspectResponse evaluates the compiled policy for the request's application.
func (e *crsPolicyEngine) InspectResponse(ctx *waf.ResponseContext) (*waf.Verdict, error) {
	set := e.current.Load()
	if set == nil || set.global == nil || ctx == nil {
		return waf.VerdictAllow, nil
	}
	engine := set.global
	if ctx.AppID != "" {
		if appEngine, ok := set.byApp[ctx.AppID]; ok {
			engine = appEngine
		}
	}
	return engine.InspectResponse(ctx)
}

// reloadCRSPolicies compiles the global policy plus every distinct per-app
// policy from the snapshot. The global engine is reloaded in place; app
// policies are cached by Config.Fingerprint, which includes the exception set.
func (m *Middleware) reloadCRSPolicies(snap *control.ConfigSnapshot) {
	if m.crsEngine == nil || snap == nil {
		return
	}

	globalConf := m.crsConfigFor(snap, "")
	if err := m.crsEngine.Reload(globalConf); err != nil {
		if m.logger != nil {
			m.logger.Error("failed to reload Coraza ruleset from snapshot", zap.Error(err))
		}
		return
	}
	if m.crsPolicies == nil {
		return
	}

	set := &crsPolicySet{global: m.crsEngine, byApp: make(map[string]*crs.Engine)}
	engines := map[string]*crs.Engine{globalConf.Fingerprint(): m.crsEngine}

	appIDs := make([]string, 0, len(snap.Apps))
	for id := range snap.Apps {
		appIDs = append(appIDs, id)
	}
	sort.Strings(appIDs)

	for _, id := range appIDs {
		conf := m.crsConfigFor(snap, id)
		key := conf.Fingerprint()
		if engine, ok := engines[key]; ok {
			set.byApp[id] = engine
			continue
		}
		engine, err := crs.New(conf)
		if err != nil {
			if m.logger != nil {
				m.logger.Error("failed to compile per-app Coraza policy",
					zap.String("app_id", id), zap.Error(err))
			}
			continue
		}
		engines[key] = engine
		set.byApp[id] = engine
	}
	m.crsPolicies.store(set)
}

// crsConfigFor resolves the effective Coraza configuration for one app. An
// empty appID yields the global policy.
func (m *Middleware) crsConfigFor(snap *control.ConfigSnapshot, appID string) crs.Config {
	conf := crs.Config{
		Mode:              crs.Mode(m.CRSMode),
		ParanoiaLevel:     m.CRSParanoiaLevel,
		InboundThreshold:  m.CRSInboundThreshold,
		OutboundThreshold: m.CRSOutboundThreshold,
		MaxBodySize:       MaxInspectionBodySize,
	}
	if conf.ParanoiaLevel == 0 {
		conf.ParanoiaLevel = crs.DefaultParanoiaLevel
	}
	if conf.InboundThreshold == 0 {
		conf.InboundThreshold = crs.DefaultInboundThreshold
	}
	if conf.OutboundThreshold == 0 {
		conf.OutboundThreshold = crs.DefaultOutboundThreshold
	}

	policy := snap.ResolveWAFPolicyFor(appID)
	// The detection mode is authoritative for enforcement: block forces the
	// ruleset to interrupt, alert keeps it in detection-only mode.
	switch control.NormalizePolicyValue(policy.DetectionMode) {
	case control.DetectionModeBlock:
		conf.Mode = crs.ModeBlock
	case control.DetectionModeAlert:
		conf.Mode = crs.ModeAudit
	}
	if policy.CRSEnabled != nil {
		conf.Disabled = !*policy.CRSEnabled
	}
	if policy.CRSParanoiaLevel > 0 {
		conf.ParanoiaLevel = policy.CRSParanoiaLevel
	}
	if policy.CRSInboundThreshold > 0 {
		conf.InboundThreshold = policy.CRSInboundThreshold
	}
	if policy.CRSOutboundThreshold > 0 {
		conf.OutboundThreshold = policy.CRSOutboundThreshold
	}

	disabledPacks := make(map[string]struct{}, len(policy.DisabledPacks))
	for _, packID := range policy.DisabledPacks {
		disabledPacks[packID] = struct{}{}
	}
	for _, pack := range snap.RulePacks {
		if pack == nil || !pack.Enabled || pack.Type == control.PackTypeNative {
			continue
		}
		if _, disabled := disabledPacks[pack.ID]; disabled {
			continue
		}
		conf.Packs = append(conf.Packs, crs.Pack{
			ID:             pack.ID,
			ReplaceBuiltin: pack.ReplaceBuiltin,
			Directives:     pack.Directives,
			Files:          pack.Files,
		})
	}

	for canonical, override := range snap.RuleOverrides {
		if override == nil {
			continue
		}
		source, id, err := control.ParseCanonicalRuleID(canonical)
		if err != nil {
			continue
		}
		ruleID, ok := numericRuleID(source, id)
		if !ok {
			continue
		}
		disabled := (override.Enabled != nil && !*override.Enabled) ||
			control.NormalizePolicyValue(override.Action) == control.RuleActionOff
		conf.Overrides = append(conf.Overrides, crs.Override{
			RuleID:   ruleID,
			Disabled: disabled,
			Alert:    control.NormalizePolicyValue(override.Action) == control.RuleActionAlert,
			Severity: override.Severity,
		})
	}

	conf.Exceptions = crsExceptionsFromSnapshot(snap.Exceptions)

	respCfg := m.responseConfigFor(snap, appID)
	if respCfg.Enabled {
		conf.InspectResponse = true
		conf.ResponseBodyLimit = respCfg.BodyLimit
		if len(respCfg.ContentTypes) > 0 {
			conf.ResponseMimeTypes = append([]string(nil), respCfg.ContentTypes...)
		}
	}

	return conf
}

// crsExceptionsFromSnapshot translates one exception row into the Coraza ctl
// action model. Semantic rule IDs and parameter-regex targets have no exact
// ctl equivalent in Coraza v3.3, so they stay semantic-only.
func crsExceptionsFromSnapshot(rules []*acl.ExceptionRule) []crs.Exception {
	exceptions := make([]crs.Exception, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || rule.ParamRegex != "" {
			continue
		}
		suppression, ok := crs.SuppressionFor(rule.RuleID, rule.Location, rule.ParamName)
		if !ok {
			continue
		}
		exceptions = append(exceptions, crs.Exception{
			Host:       rule.Host,
			PathPrefix: rule.PathPrefix,
			PathRegex:  rule.PathRegex,
			Method:     rule.Method,
			Location:   rule.Location,
			ParamName:  rule.ParamName,
			RuleID:     suppression.RuleID,
		})
	}
	return exceptions
}
