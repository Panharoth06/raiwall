package crs

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func requestContext(query string) *waf.RequestContext {
	return &waf.RequestContext{
		Method:  http.MethodGet,
		Host:    "example.com",
		Path:    "/search",
		Query:   query,
		Headers: http.Header{},
	}
}

// TestEngine_CompilesAndDetects proves the vendored CRS compiles under Coraza
// and that the canonical SQLi/XSS vectors cross the anomaly threshold.
func TestEngine_CompilesAndDetects(t *testing.T) {
	engine, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}

	cases := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"sqli quoted boolean", url.Values{"q": {"1' OR '1'='1"}}.Encode(), true},
		{"sqli union", url.Values{"q": {"1 UNION SELECT NULL--"}}.Encode(), true},
		{"xss script", url.Values{"q": {"<script>alert(1)</script>"}}.Encode(), true},
		{"lfi traversal", url.Values{"q": {"../../etc/passwd"}}.Encode(), true},
		{"benign search", url.Values{"q": {"wireless headphones"}}.Encode(), false},
		{"benign filter", url.Values{"category": {"electronics"}, "page": {"2"}}.Encode(), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := engine.InspectRequest(requestContext(tc.query))
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			if tc.blocked {
				if verdict.Action != waf.ActionBlock {
					t.Fatalf("expected block, got %s (rule %s)", verdict.Action, verdict.RuleID)
				}
				if verdict.Engine != "crs" || verdict.AnomalyScore <= 0 {
					t.Fatalf("expected CRS metadata, got %+v", verdict)
				}
				if len(verdict.MatchedRules) == 0 {
					t.Fatal("expected matched rules")
				}
			} else if verdict.Action != waf.ActionAllow {
				t.Fatalf("expected allow, got %s (%s)", verdict.Action, verdict.Reason)
			}
		})
	}
}

// TestEngine_DetectsScannerUserAgent covers a CRS-only signal: the semantic
// engine does not recognize scanner user agents, but CRS rule 913100 does.
func TestEngine_DetectsScannerUserAgent(t *testing.T) {
	engine, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}

	ctx := requestContext("")
	ctx.Headers.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
	verdict, err := engine.InspectRequest(ctx)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionBlock {
		t.Fatalf("expected scanner block, got %s", verdict.Action)
	}
}

func TestEngine_ResponseInspectionDisabled(t *testing.T) {
	engine, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}
	verdict, err := engine.InspectResponse(&waf.ResponseContext{StatusCode: 200, Headers: http.Header{}})
	if err != nil {
		t.Fatalf("inspect response: %v", err)
	}
	if verdict.Action != waf.ActionAllow {
		t.Fatalf("expected allow until paired response transactions ship, got %s", verdict.Action)
	}
}

func TestEngine_AuditModeDoesNotBlock(t *testing.T) {
	engine, err := New(Config{Mode: ModeAudit, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}
	verdict, err := engine.InspectRequest(requestContext(url.Values{"q": {"1' OR '1'='1"}}.Encode()))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionAudit {
		t.Fatalf("expected audit, got %s", verdict.Action)
	}
}
