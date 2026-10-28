package caddy

import (
	"context"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

// aclEngineInstances tracks every provisioned middleware so one deploy hook can
// refresh them all. Caddy provisions one instance per site while the active
// configuration snapshot is process-wide.
var (
	aclEngineInstances sync.Map
	aclEngineHookOnce  sync.Once
)

// syncACLEngineFromSnapshot replaces the running ACL engine with one compiled
// from the committed snapshot. Access rules are part of the versioned config,
// so an empty snapshot genuinely clears rules that were previously active.
func (m *Middleware) syncACLEngineFromSnapshot(snap *control.ConfigSnapshot) {
	if snap == nil {
		return
	}

	engine, err := acl.NewACLEngine(m.bartTable, m.geoIPReader, snap.ACLRules...)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to compile ACL engine from snapshot", zap.Error(err))
		}
		return
	}
	if m.ipGroupMgr != nil {
		engine.SetIPGroupManager(m.ipGroupMgr)
	}
	m.SetACLEngine(engine)
}

// installACLEngineDeployHook loads the active snapshot once and keeps this
// middleware in sync with every later deploy. Without it the data plane keeps
// evaluating the rule set captured at process start, which is why console
// edits and status toggles appeared to be ignored.
func (m *Middleware) installACLEngineDeployHook() {
	aclEngineInstances.Store(m, struct{}{})
	aclEngineHookOnce.Do(func() {
		control.RegisterDeployHook(func(_ context.Context, snap *control.ConfigSnapshot) {
			aclEngineInstances.Range(func(key, _ any) bool {
				if mw, ok := key.(*Middleware); ok {
					mw.syncACLEngineFromSnapshot(snap)
				}
				return true
			})
		})
	})

	m.syncACLEngineFromSnapshot(control.GetActiveSnapshot())
}
