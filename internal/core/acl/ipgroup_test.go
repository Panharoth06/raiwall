package acl

import (
	"net"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPGroupManager_BuiltinsAndMatching(t *testing.T) {
	mgr := NewIPGroupManager(nil)
	require.NotNil(t, mgr)

	// Verify Search Spiders
	spiders, ok := mgr.GetGroup("search_spiders")
	require.True(t, ok)
	assert.Equal(t, "system", spiders.Type)

	// Googlebot test IP
	googleIP := net.ParseIP("66.249.66.1")
	assert.True(t, mgr.InGroup(googleIP, "search_spiders"))
	assert.True(t, mgr.InGroupStr("66.249.66.1", "search_spiders"))

	// Bingbot test IP
	bingIP := net.ParseIP("157.55.39.10")
	assert.True(t, mgr.InGroup(bingIP, "search_spiders"))

	// Baiduspider test IP
	baiduIP := net.ParseIP("180.76.15.20")
	assert.True(t, mgr.InGroup(baiduIP, "search_spiders"))

	// Standard public IP should not match
	userIP := net.ParseIP("8.8.8.8")
	assert.False(t, mgr.InGroup(userIP, "search_spiders"))

	// Verify Malicious Threat Intel
	threatIP := net.ParseIP("185.220.101.42")
	assert.True(t, mgr.InGroup(threatIP, "malicious_threat_intel"))
	assert.False(t, mgr.InGroup(userIP, "malicious_threat_intel"))
}

func TestIPGroupManager_DynamicAddAndRemove(t *testing.T) {
	mgr := NewIPGroupManager(nil)
	grp, err := mgr.CreateGroup("custom_partner_ips", "Allowed API Partners", "custom")
	require.NoError(t, err)
	require.NotNil(t, grp)

	partnerIP := net.ParseIP("192.0.2.55")
	assert.False(t, mgr.InGroup(partnerIP, grp.Name))

	// Add single IP / CIDR
	entry, err := mgr.AddCIDR(grp.ID, "192.0.2.0/24", "Partner subnet")
	require.NoError(t, err)
	require.NotNil(t, entry)

	// Should match immediately
	assert.True(t, mgr.InGroup(partnerIP, grp.Name))
	assert.True(t, mgr.InGroupStr("192.0.2.55", grp.Name))

	// List entries
	entries := mgr.ListEntries(grp.ID)
	assert.Len(t, entries, 1)

	// Remove entry
	err = mgr.RemoveCIDR(grp.ID, entry.ID)
	require.NoError(t, err)
	assert.False(t, mgr.InGroup(partnerIP, grp.Name))

	// Delete group
	err = mgr.DeleteGroup(grp.ID)
	require.NoError(t, err)
	_, found := mgr.GetGroup(grp.ID)
	assert.False(t, found)
}

func TestIPGroup_ExprEngineIntegration(t *testing.T) {
	bt := NewBARTTable()
	engine, err := NewACLEngine(bt, nil)
	require.NoError(t, err)

	mgr := engine.IPGroupManager()
	require.NotNil(t, mgr)

	// Add ACL rules using `client_ip in ip_group(...)` and `in_ip_group(...)`
	rule1 := &ACLRule{
		Name:       "allow-search-spiders",
		Expression: `client_ip in ip_group("search_spiders")`,
		Action:     ActionAllow,
		Priority:   10,
	}
	rule2 := &ACLRule{
		Name:       "block-threat-intel",
		Expression: `client_ip in ip_group("malicious_threat_intel")`,
		Action:     ActionBlock,
		Priority:   20,
		StatusCode: 403,
	}
	rule3 := &ACLRule{
		Name:       "fn-search-spiders",
		Expression: `in_ip_group(client_ip, "search_spiders")`,
		Action:     ActionAllow,
		Priority:   30,
	}

	require.NoError(t, engine.AddRule(rule1))
	require.NoError(t, engine.AddRule(rule2))
	require.NoError(t, engine.AddRule(rule3))

	// 1. Googlebot should match allow-search-spiders
	reqGoogle := &waf.RequestContext{
		ClientIP: net.ParseIP("66.249.66.50"),
		Path:     "/blog/article-1",
	}
	vGoogle, err := engine.EvaluateRequest(reqGoogle)
	require.NoError(t, err)
	assert.True(t, vGoogle.Matched)
	assert.Equal(t, "allow-search-spiders", vGoogle.RuleName)
	assert.Equal(t, ActionAllow, vGoogle.Action)

	// 2. Threat IP should match block-threat-intel
	reqThreat := &waf.RequestContext{
		ClientIP: net.ParseIP("185.220.101.88"),
		Path:     "/login",
	}
	vThreat, err := engine.EvaluateRequest(reqThreat)
	require.NoError(t, err)
	assert.True(t, vThreat.Matched)
	assert.Equal(t, "block-threat-intel", vThreat.RuleName)
	assert.Equal(t, ActionBlock, vThreat.Action)
	assert.Equal(t, 403, vThreat.StatusCode)

	// 3. Normal user should not match either rule
	reqNormal := &waf.RequestContext{
		ClientIP: net.ParseIP("8.8.8.8"),
		Path:     "/login",
	}
	vNormal, err := engine.EvaluateRequest(reqNormal)
	require.NoError(t, err)
	assert.False(t, vNormal.Matched)

	// 4. Test slice in operator
	ruleSlice := &ACLRule{
		Name:       "allow-countries",
		Expression: `geo.Country in ["US", "DE"]`,
		Action:     ActionAllow,
		Priority:   5,
	}
	err = engine.AddRule(ruleSlice)
	require.NoError(t, err)
	vSlice, err := engine.Evaluate(reqNormal, GeoData{Country: "DE"})
	require.NoError(t, err)
	assert.True(t, vSlice.Matched)
	assert.Equal(t, "allow-countries", vSlice.RuleName)
}

func BenchmarkIPGroup_BARTLookup(b *testing.B) {
	mgr := NewIPGroupManager(nil)
	mgr.PopulateSyntheticThreats(5000)

	testIP := net.ParseIP("198.18.5.120")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.InGroup(testIP, "malicious_threat_intel")
	}
}
