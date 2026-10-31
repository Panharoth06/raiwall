package caddy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/stretchr/testify/require"
)

func sqliRequest(appID, host, path string) *waf.RequestContext {
	return &waf.RequestContext{
		AppID:   appID,
		Method:  http.MethodGet,
		Host:    host,
		Path:    path,
		Query:   url.Values{"q": {"1' OR '1'='1"}}.Encode(),
		Headers: http.Header{},
	}
}

func newPolicyTestMiddleware(t *testing.T) *Middleware {
	t.Helper()
	engine, err := crs.New(crs.Config{Mode: crs.ModeBlock, ParanoiaLevel: 1})
	require.NoError(t, err)
	return &Middleware{
		crsEngine:            engine,
		crsPolicies:          newCRSPolicyEngine(),
		CRSMode:              "block",
		CRSParanoiaLevel:     1,
		CRSInboundThreshold:  5,
		CRSOutboundThreshold: 4,
	}
}

func TestCRSPoliciesSelectPerAppEnabledState(t *testing.T) {
	m := newPolicyTestMiddleware(t)

	snap := control.NewConfigSnapshot(2, control.ModeDefense, []*control.AppConfig{
		{ID: "app-off", Name: "Off", Hostnames: []string{"off.example.com"}, Mode: control.ModeDefense},
		{ID: "app-on", Name: "On", Hostnames: []string{"on.example.com"}, Mode: control.ModeDefense},
	})
	disabled := false
	snap.Apps["app-off"].WAFPolicy = &control.WAFPolicySnapshot{CRSEnabled: &disabled}

	m.reloadCorazaFromSnapshot(snap)

	off, err := m.crsPolicies.InspectRequest(sqliRequest("app-off", "off.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionAllow, off.Action, "per-app policy must disable CRS")

	on, err := m.crsPolicies.InspectRequest(sqliRequest("app-on", "on.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, on.Action, "an app without an override inherits the global policy")

	global, err := m.crsPolicies.InspectRequest(sqliRequest("", "other.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, global.Action)
}

func TestCRSPoliciesApplySnapshotExceptions(t *testing.T) {
	m := newPolicyTestMiddleware(t)

	snap := control.NewConfigSnapshot(3, control.ModeDefense, []*control.AppConfig{
		{ID: "app-x", Name: "X", Hostnames: []string{"x.example.com"}, Mode: control.ModeDefense},
	})
	snap.Exceptions = []*acl.ExceptionRule{{
		ID:         "exc-sqli-1",
		Host:       "x.example.com",
		PathPrefix: "/search",
		RuleID:     "949110", // CRS anomaly-evaluation rule
	}}

	m.reloadCorazaFromSnapshot(snap)

	scoped, err := m.crsPolicies.InspectRequest(sqliRequest("app-x", "x.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionAllow, scoped.Action, "the exception must remove the blocking rule")

	unscoped, err := m.crsPolicies.InspectRequest(sqliRequest("app-x", "x.example.com", "/admin"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, unscoped.Action, "the exception must stay scoped to its path")

	otherHost, err := m.crsPolicies.InspectRequest(sqliRequest("app-x", "y.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, otherHost.Action, "the exception must stay scoped to its host")
}

func TestCRSPoliciesRespectPerAppAlertMode(t *testing.T) {
	m := newPolicyTestMiddleware(t)

	snap := control.NewConfigSnapshot(5, control.ModeDefense, []*control.AppConfig{
		{ID: "app-audit", Name: "Audit", Hostnames: []string{"audit.example.com"}, Mode: control.ModeDefense},
	})
	snap.Apps["app-audit"].WAFPolicy = &control.WAFPolicySnapshot{DetectionMode: control.DetectionModeAlert}

	m.reloadCorazaFromSnapshot(snap)

	verdict, err := m.crsPolicies.InspectRequest(sqliRequest("app-audit", "audit.example.com", "/search"))
	require.NoError(t, err)
	require.Equal(t, waf.ActionAudit, verdict.Action, "a per-app alert policy must not block")
}

func TestCRSPoliciesHotReloadPerAppPolicy(t *testing.T) {
	m := newPolicyTestMiddleware(t)

	snap := control.NewConfigSnapshot(6, control.ModeDefense, []*control.AppConfig{
		{ID: "app-h", Name: "H", Hostnames: []string{"h.example.com"}, Mode: control.ModeDefense},
	})
	disabled := false
	snap.Apps["app-h"].WAFPolicy = &control.WAFPolicySnapshot{CRSEnabled: &disabled}
	m.reloadCorazaFromSnapshot(snap)

	req := func() *waf.RequestContext {
		return sqliRequest("app-h", "h.example.com", "/search")
	}
	verdict, err := m.crsPolicies.InspectRequest(req())
	require.NoError(t, err)
	require.Equal(t, waf.ActionAllow, verdict.Action)

	// Clear the override and redeploy the same process without a restart.
	snap.Apps["app-h"].WAFPolicy = nil
	m.reloadCorazaFromSnapshot(snap)

	verdict, err = m.crsPolicies.InspectRequest(req())
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, verdict.Action, "hot reload must pick up the cleared override")
}

func TestCRSPoliciesShareEnginesForIdenticalPolicies(t *testing.T) {
	m := newPolicyTestMiddleware(t)

	snap := control.NewConfigSnapshot(4, control.ModeDefense, []*control.AppConfig{
		{ID: "a", Name: "A", Hostnames: []string{"a.example.com"}, Mode: control.ModeDefense},
		{ID: "b", Name: "B", Hostnames: []string{"b.example.com"}, Mode: control.ModeDefense},
	})
	m.reloadCorazaFromSnapshot(snap)

	set := m.crsPolicies.current.Load()
	require.NotNil(t, set)
	require.Same(t, set.global, set.byApp["a"], "apps inheriting the global policy must reuse its engine")
	require.Same(t, set.global, set.byApp["b"])
}
