package acl

import (
	"net"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func TestACLEngine_CompilationAndEvaluation(t *testing.T) {
	bartTable := NewBARTTable()
	_ = bartTable.InsertCIDR("198.51.100.0/24", "tor", "")
	_ = bartTable.InsertCIDR("203.0.113.5", "spammer", "")

	rules := []*ACLRule{
		{
			Name:       "whitelist-internal",
			Expression: `in_cidr(ip, "10.0.0.0/8") || has_prefix(path, "/healthz")`,
			Action:     ActionAllow,
			Priority:   10,
		},
		{
			Name:       "block-tor",
			Expression: `in_feed(ip, "tor")`,
			Action:     ActionBlock,
			Priority:   20,
			StatusCode: 403,
		},
		{
			Name:       "geo-fencing",
			Expression: `geo.Country == "KP" || geo.Country == "IR"`,
			Action:     ActionBlock,
			Priority:   30,
			StatusCode: 451,
		},
		{
			Name:        "redirect-admin",
			Expression:  `path == "/admin" && headers["x-admin-token"] != "secret"`,
			Action:      ActionRedirect,
			Priority:    40,
			StatusCode:  302,
			RedirectURL: "/login",
		},
		{
			Name:       "challenge-suspicious",
			Expression: `user_agent contains "Scraper" || regex_match("^/api/v1/export.*$", path)`,
			Action:     ActionChallenge,
			Priority:   50,
		},
	}

	aclEngine, err := NewACLEngine(bartTable, nil, rules...)
	if err != nil {
		t.Fatalf("NewACLEngine error: %v", err)
	}

	tests := []struct {
		name         string
		reqCtx       *waf.RequestContext
		geo          GeoData
		wantMatched  bool
		wantRuleName string
		wantAction   Action
		wantStatus   int
	}{
		{
			name: "allow internal IP via CIDR",
			reqCtx: &waf.RequestContext{
				ClientIP: net.ParseIP("10.5.2.1"),
				Path:     "/api/users",
			},
			wantMatched:  true,
			wantRuleName: "whitelist-internal",
			wantAction:   ActionAllow,
		},
		{
			name: "allow healthcheck path prefix",
			reqCtx: &waf.RequestContext{
				ClientIP: net.ParseIP("8.8.8.8"),
				Path:     "/healthz/readiness",
			},
			wantMatched:  true,
			wantRuleName: "whitelist-internal",
			wantAction:   ActionAllow,
		},
		{
			name: "block tor threat feed IP",
			reqCtx: &waf.RequestContext{
				ClientIP: net.ParseIP("198.51.100.42"),
				Path:     "/checkout",
			},
			wantMatched:  true,
			wantRuleName: "block-tor",
			wantAction:   ActionBlock,
			wantStatus:   403,
		},
		{
			name: "block geo fencer country",
			reqCtx: &waf.RequestContext{
				ClientIP: net.ParseIP("203.0.113.10"),
				Path:     "/products",
			},
			geo:          GeoData{Country: "KP"},
			wantMatched:  true,
			wantRuleName: "geo-fencing",
			wantAction:   ActionBlock,
			wantStatus:   451,
		},
		{
			name: "redirect admin route without auth token",
			reqCtx: &waf.RequestContext{
				ClientIP: net.ParseIP("203.0.113.20"),
				Path:     "/admin",
			},
			geo:          GeoData{Country: "US"},
			wantMatched:  true,
			wantRuleName: "redirect-admin",
			wantAction:   ActionRedirect,
			wantStatus:   302,
		},
		{
			name: "challenge scraper user-agent",
			reqCtx: &waf.RequestContext{
				ClientIP:  net.ParseIP("203.0.113.30"),
				Path:      "/catalog",
				UserAgent: "DataScraper/1.0",
			},
			geo:          GeoData{Country: "DE"},
			wantMatched:  true,
			wantRuleName: "challenge-suspicious",
			wantAction:   ActionChallenge,
		},
		{
			name: "benign non-matching request allows through",
			reqCtx: &waf.RequestContext{
				ClientIP:  net.ParseIP("203.0.113.40"),
				Path:      "/about",
				UserAgent: "Mozilla/5.0",
			},
			geo:         GeoData{Country: "US"},
			wantMatched: false,
			wantAction:  ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := aclEngine.Evaluate(tt.reqCtx, tt.geo)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if verdict.Matched != tt.wantMatched {
				t.Errorf("Matched = %v, want %v", verdict.Matched, tt.wantMatched)
			}
			if tt.wantMatched && verdict.RuleName != tt.wantRuleName {
				t.Errorf("RuleName = %q, want %q", verdict.RuleName, tt.wantRuleName)
			}
			if verdict.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", verdict.Action, tt.wantAction)
			}
			if tt.wantStatus != 0 && verdict.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", verdict.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestACLEngine_InvalidExpression(t *testing.T) {
	rule := &ACLRule{
		Name:       "bad-syntax",
		Expression: `this is not a valid expression !@#$`,
		Action:     ActionBlock,
	}
	aclEngine, _ := NewACLEngine(nil, nil)
	if err := aclEngine.AddRule(rule); err == nil {
		t.Errorf("expected compilation error for invalid expression")
	}
}

func TestACLEngine_ContainsFunction(t *testing.T) {
	rule := &ACLRule{
		Name:       "test-contains",
		Expression: `user_agent contains "BadBot" || str_contains(path, "forbidden")`,
		Action:     ActionBlock,
		StatusCode: 403,
	}
	aclEng, err := NewACLEngine(nil, nil, rule)
	if err != nil {
		t.Fatalf("failed to compile rule with contains function: %v", err)
	}

	reqCtx := &waf.RequestContext{
		Path:      "/public/forbidden/resource",
		UserAgent: "Mozilla/5.0",
	}
	verdict, err := aclEng.EvaluateRequest(reqCtx)
	if err != nil {
		t.Fatalf("EvaluateRequest error: %v", err)
	}
	if !verdict.Matched || verdict.Action != ActionBlock {
		t.Errorf("expected rule to match on contains(path, forbidden), got %v", verdict)
	}
}

func TestACLEngine_SetBARTTable_Recompile(t *testing.T) {
	rule := &ACLRule{
		Name:       "feed-rule",
		Expression: `in_feed(ip, "tor")`,
		Action:     ActionBlock,
		StatusCode: 403,
	}
	// Initialized with nil BARTTable
	aclEng, err := NewACLEngine(nil, nil, rule)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	reqCtx := &waf.RequestContext{
		ClientIP: net.ParseIP("198.51.100.42"),
	}

	// Initially nil BARTTable -> does not match
	v1, err := aclEng.EvaluateRequest(reqCtx)
	if err != nil || v1.Matched {
		t.Fatalf("expected no match before SetBARTTable, got %v", v1)
	}

	// Set BARTTable dynamically
	bt := NewBARTTable()
	_ = bt.InsertCIDR("198.51.100.0/24", "tor", "")
	aclEng.SetBARTTable(bt)

	// Now should match because rules were recompiled with bt
	v2, err := aclEng.EvaluateRequest(reqCtx)
	if err != nil || !v2.Matched {
		t.Fatalf("expected match after SetBARTTable, got %v", v2)
	}
}

func TestACLEngine_QueryUnescapeAndOrder(t *testing.T) {
	rule := &ACLRule{
		Name:       "query-rule",
		Expression: `query["search"] == "cyber attack" && query["tag"] == "first"`,
		Action:     ActionBlock,
		StatusCode: 403,
	}
	aclEng, err := NewACLEngine(nil, nil, rule)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	reqCtx := &waf.RequestContext{
		Query: "search=cyber%20attack&tag=first&tag=second",
	}
	v, err := aclEng.EvaluateRequest(reqCtx)
	if !v.Matched {
		t.Errorf("expected query parameters to be unescaped and preserve first value")
	}
}

func TestACLEngine_InOperatorCompatibility(t *testing.T) {
	rule := &ACLRule{
		Name:       "in-slice-rule",
		Expression: `method in ["POST", "PUT"]`,
		Action:     ActionBlock,
		StatusCode: 403,
	}
	aclEng, err := NewACLEngine(nil, nil, rule)
	if err != nil {
		t.Fatalf("failed to create engine with slice in operator: %v", err)
	}

	reqCtx := &waf.RequestContext{
		Method: "POST",
	}
	v, err := aclEng.EvaluateRequest(reqCtx)
	if err != nil {
		t.Fatalf("EvaluateRequest error: %v", err)
	}
	if !v.Matched {
		t.Errorf("expected POST method to match rule")
	}
}
