package caddy

import (
	"net"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncACLEngineFromSnapshot_ReplacesRules(t *testing.T) {
	reqCtx := &waf.RequestContext{
		ClientIP: net.ParseIP("198.51.100.7"),
		Method:   "GET",
		Host:     "demo.localhost",
		Path:     "/console",
		Headers:  map[string][]string{},
	}

	blockRule := &acl.ACLRule{
		Name:       "block_console",
		Expression: "has_prefix(path, '/console')",
		Action:     acl.ActionBlock,
		Priority:   10,
		StatusCode: 403,
	}

	m := &Middleware{}
	snap := &control.ConfigSnapshot{Version: 2, ACLRules: []*acl.ACLRule{blockRule}}
	m.syncACLEngineFromSnapshot(snap)

	engine := m.ACLEngine()
	require.NotNil(t, engine)
	verdict, err := engine.EvaluateRequest(reqCtx)
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Matched)
	assert.Equal(t, acl.ActionBlock, verdict.Action)

	// A deploy that drops the rule must clear it from the data plane, which is
	// what makes disabling a rule through the console effective.
	m.syncACLEngineFromSnapshot(&control.ConfigSnapshot{Version: 3})
	cleared, err := m.ACLEngine().EvaluateRequest(reqCtx)
	require.NoError(t, err)
	assert.False(t, cleared.Matched)
}

func TestSyncACLEngineFromSnapshot_KeepsContinueInspection(t *testing.T) {
	m := &Middleware{}
	m.syncACLEngineFromSnapshot(&control.ConfigSnapshot{
		Version: 2,
		ACLRules: []*acl.ACLRule{{
			Name:               "allow_with_inspection",
			Expression:         "has_prefix(path, '/ci')",
			Action:             acl.ActionAllow,
			Priority:           10,
			ContinueInspection: true,
		}},
	})

	verdict, err := m.ACLEngine().EvaluateRequest(&waf.RequestContext{
		ClientIP: net.ParseIP("198.51.100.7"),
		Method:   "GET",
		Host:     "demo.localhost",
		Path:     "/ci",
		Headers:  map[string][]string{},
	})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Matched)
	assert.True(t, verdict.ContinueInspection)
}
