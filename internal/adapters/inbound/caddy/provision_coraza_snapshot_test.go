package caddy

import (
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/stretchr/testify/require"
)

func TestReloadCorazaFromSnapshot_HotSwapsPacksAndOverrides(t *testing.T) {
	engine, err := crs.New(crs.Config{Mode: crs.ModeBlock, ParanoiaLevel: 1})
	require.NoError(t, err)

	m := &Middleware{
		crsEngine:            engine,
		CRSMode:              "block",
		CRSParanoiaLevel:     1,
		CRSInboundThreshold:  5,
		CRSOutboundThreshold: 4,
	}

	snap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	snap.RulePacks = []*control.RulePackSnapshot{{
		ID:         "custom",
		Name:       "Custom ModSec",
		Version:    "1.0.0",
		Type:       control.PackTypeModsec,
		Enabled:    true,
		Directives: `SecRule REQUEST_URI "@contains /evil" "id:10001,phase:1,deny,status:403,msg:'custom block'"`,
	}}

	inspect := func() *waf.Verdict {
		verdict, err := engine.InspectRequest(&waf.RequestContext{
			Method:  http.MethodGet,
			Host:    "example.com",
			Path:    "/evil",
			Headers: http.Header{},
		})
		require.NoError(t, err)
		return verdict
	}

	m.reloadCorazaFromSnapshot(snap)
	require.Equal(t, waf.ActionBlock, inspect().Action)

	alert := control.RuleActionAlert
	snap.RuleOverrides = map[string]*control.RuleOverrideSnapshot{
		"pack:custom:10001": {Action: alert},
	}
	m.reloadCorazaFromSnapshot(snap)
	require.Equal(t, waf.ActionAudit, inspect().Action)

	off := control.RuleActionOff
	snap.RuleOverrides["pack:custom:10001"] = &control.RuleOverrideSnapshot{Action: off}
	m.reloadCorazaFromSnapshot(snap)
	require.NotEqual(t, waf.ActionBlock, inspect().Action)
}
