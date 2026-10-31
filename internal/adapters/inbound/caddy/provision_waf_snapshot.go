package caddy

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
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

// reloadCorazaFromSnapshot recompiles the global and per-app Coraza policies
// from the snapshot. Compilation happens before the pointer swap; a failure
// keeps the previous generation serving traffic.
func (m *Middleware) reloadCorazaFromSnapshot(snap *control.ConfigSnapshot) {
	m.reloadCRSPolicies(snap)
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
