package caddy

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"go.uber.org/zap"
)

// wafEngineInstances tracks every provisioned middleware so one deploy hook can
// refresh their detection state. Caddy provisions one instance per site while
// the active configuration snapshot is process-wide.
var (
	wafEngineInstances sync.Map
	wafEngineHookOnce  sync.Once
)

// installWAFEngineDeployHook keeps exception rules and imported native
// signatures in sync with the committed snapshot. Without it, API-created
// exceptions and imported rules only take effect after a process restart.
func (m *Middleware) installWAFEngineDeployHook() {
	wafEngineInstances.Store(m, struct{}{})
	wafEngineHookOnce.Do(func() {
		control.RegisterDeployHook(func(_ context.Context, snap *control.ConfigSnapshot) {
			wafEngineInstances.Range(func(key, _ any) bool {
				if mw, ok := key.(*Middleware); ok {
					mw.syncWAFEnginesFromSnapshot(snap)
				}
				return true
			})
		})
	})

	m.syncWAFEnginesFromSnapshot(control.GetActiveSnapshot())
}

// syncWAFEnginesFromSnapshot rebuilds derived detection engines from the
// snapshot. Compilation happens before any pointer swap; a failure leaves the
// previous engines serving traffic.
func (m *Middleware) syncWAFEnginesFromSnapshot(snap *control.ConfigSnapshot) {
	if snap == nil {
		return
	}

	exceptionEngine, err := acl.NewExceptionEngine(snap.Exceptions...)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to compile exception engine from snapshot", zap.Error(err))
		}
	} else {
		m.SetExceptionEngine(exceptionEngine)
	}

	rules, err := cve.BundledRules()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to load bundled virtual patches", zap.Error(err))
		}
		return
	}
	for _, pack := range snap.RulePacks {
		if pack == nil || !pack.Enabled || pack.Type != control.PackTypeNative {
			continue
		}
		for _, sig := range pack.Rules {
			sig.ID = pack.ID + ":" + sig.ID
			rules = append(rules, sig)
		}
	}

	innerEngine, err := cve.NewEngine(rules)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to compile virtual-patch engine from snapshot", zap.Error(err))
		}
		return
	}
	innerEngine.SetStateSource(control.SnapshotInnerRuleState)
	m.SetInnerRules(innerEngine)

	m.reloadCorazaFromSnapshot(snap)
}

// reloadCorazaFromSnapshot recompiles the Coraza ruleset with the snapshot's
// ModSecurity/CRS packs and per-rule overrides. Compilation happens before the
// pointer swap; a failure keeps the previous engine serving traffic.
func (m *Middleware) reloadCorazaFromSnapshot(snap *control.ConfigSnapshot) {
	if m.crsEngine == nil || snap == nil {
		return
	}

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
	policy := snap.ResolveWAFPolicyFor("")
	// The detection mode is authoritative for enforcement: block forces the
	// Coraza ruleset to interrupt, alert keeps it in detection-only mode.
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

	if err := m.crsEngine.Reload(conf); err != nil {
		if m.logger != nil {
			m.logger.Error("failed to reload Coraza ruleset from snapshot", zap.Error(err))
		}
	}
}

func numericRuleID(source, id string) (int, bool) {
	switch source {
	case control.RuleSourceCRS:
		ruleID, err := strconv.Atoi(id)
		return ruleID, err == nil
	case control.RuleSourcePack:
		if idx := strings.LastIndex(id, ":"); idx >= 0 {
			id = id[idx+1:]
		}
		ruleID, err := strconv.Atoi(id)
		return ruleID, err == nil
	default:
		return 0, false
	}
}
