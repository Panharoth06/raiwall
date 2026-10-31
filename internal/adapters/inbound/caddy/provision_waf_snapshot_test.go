package caddy

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/stretchr/testify/require"
)

func TestSyncWAFEnginesFromSnapshot_AppliesNativeRulesAndExceptions(t *testing.T) {
	m := &Middleware{engine: waf.NewSemanticEngine()}

	snap := control.NewConfigSnapshot(2, control.ModeDefense, nil)
	snap.RulePacks = []*control.RulePackSnapshot{{
		ID:      "pack1",
		Name:    "Custom Pack",
		Version: "1.0.0",
		Type:    control.PackTypeNative,
		Enabled: true,
		Rules: []cve.Signature{{
			ID:       "r1",
			Name:     "Evil path",
			Category: "rce",
			Matches:  []cve.TokenRef{{Field: cve.FieldPath, Token: "/evil"}},
		}},
	}}
	snap.Exceptions = []*acl.ExceptionRule{{
		ID:         "exc-1",
		Host:       "example.com",
		PathPrefix: "/evil",
		RuleID:     "pack1:r1",
	}}

	m.syncWAFEnginesFromSnapshot(snap)

	require.NotNil(t, m.ExceptionEngine())

	// No exception for another host: the imported signature blocks.
	verdict, err := m.engine.InspectRequest(&waf.RequestContext{
		Host:   "other.test",
		Method: "GET",
		Path:   "/evil",
	})
	require.NoError(t, err)
	require.Equal(t, waf.ActionBlock, verdict.Action)
	require.Equal(t, "pack1:r1", verdict.RuleID)

	// The snapshot exception suppresses the same signature on example.com.
	verdict, err = m.engine.InspectRequest(&waf.RequestContext{
		Host:   "example.com",
		Method: "GET",
		Path:   "/evil",
	})
	require.NoError(t, err)
	require.NotEqual(t, waf.ActionBlock, verdict.Action)
}
