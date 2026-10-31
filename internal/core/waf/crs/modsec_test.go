package crs

import (
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

const customRule = `SecRule REQUEST_URI "@contains /evil" "id:10001,phase:1,deny,status:403,msg:'custom block'"`

func inspectPath(t *testing.T, engine *Engine, path string) *waf.Verdict {
	t.Helper()
	verdict, err := engine.InspectRequest(&waf.RequestContext{
		Method:  http.MethodGet,
		Host:    "example.com",
		Path:    path,
		Headers: http.Header{},
	})
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	return verdict
}

func TestEngine_ImportedModsecPack(t *testing.T) {
	engine, err := New(Config{
		Mode:          ModeBlock,
		ParanoiaLevel: 1,
		Packs:         []Pack{{ID: "custom", Directives: customRule}},
	})
	if err != nil {
		t.Fatalf("compile pack: %v", err)
	}

	blocked := inspectPath(t, engine, "/evil")
	if blocked.Action != waf.ActionBlock || blocked.RuleID != "CRS_10001" {
		t.Fatalf("expected custom rule block, got %+v", blocked)
	}

	benign := inspectPath(t, engine, "/health")
	if benign.Action != waf.ActionAllow {
		t.Fatalf("expected benign request to pass, got %+v", benign)
	}
}

func TestEngine_RuleOverrides(t *testing.T) {
	base := Config{
		Mode:          ModeBlock,
		ParanoiaLevel: 1,
		Packs:         []Pack{{ID: "custom", Directives: customRule}},
	}

	base.Overrides = []Override{{RuleID: 10001, Disabled: true}}
	disabled, err := New(base)
	if err != nil {
		t.Fatalf("compile disabled override: %v", err)
	}
	if v := inspectPath(t, disabled, "/evil"); v.Action != waf.ActionAllow {
		t.Fatalf("expected disabled rule to pass, got %+v", v)
	}

	base.Overrides = []Override{{RuleID: 10001, Alert: true}}
	alert, err := New(base)
	if err != nil {
		t.Fatalf("compile alert override: %v", err)
	}
	if v := inspectPath(t, alert, "/evil"); v.Action != waf.ActionAudit {
		t.Fatalf("expected alert override to audit, got %+v", v)
	}

	base.Overrides = []Override{{RuleID: 10001, Severity: "critical"}}
	severity, err := New(base)
	if err != nil {
		t.Fatalf("compile severity override: %v", err)
	}
	verdict := inspectPath(t, severity, "/evil")
	if len(verdict.MatchedRules) == 0 || verdict.MatchedRules[0].Severity != "critical" {
		t.Fatalf("expected severity override to surface critical, got %+v", verdict.MatchedRules)
	}
}

func TestEngine_SeverityOverrideOnEmbeddedCRS(t *testing.T) {
	engine, err := New(Config{
		Mode:          ModeBlock,
		ParanoiaLevel: 1,
		Overrides:     []Override{{RuleID: 913100, Severity: "low"}},
	})
	if err != nil {
		t.Fatalf("compile severity override: %v", err)
	}

	verdict, err := engine.InspectRequest(&waf.RequestContext{
		Method:  http.MethodGet,
		Host:    "example.com",
		Path:    "/api/probe",
		Headers: http.Header{"User-Agent": {"sqlmap/1.0"}},
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionBlock {
		t.Fatalf("expected block, got %+v", verdict)
	}
	if verdict.Severity != "low" {
		t.Fatalf("expected low severity, got %q", verdict.Severity)
	}
	for _, match := range verdict.MatchedRules {
		if match.RuleID == "913100" && match.Severity != "low" {
			t.Fatalf("expected matched rule severity low, got %q", match.Severity)
		}
	}
}

func TestEngine_ReplacementPackSuppressesEmbeddedCRS(t *testing.T) {
	engine, err := New(Config{
		Mode:          ModeBlock,
		ParanoiaLevel: 1,
		Packs: []Pack{{
			ID:             "replacement",
			ReplaceBuiltin: true,
			Directives:     customRule,
		}},
	})
	if err != nil {
		t.Fatalf("compile replacement pack: %v", err)
	}

	// A vector that embedded CRS would block is allowed by the replacement.
	verdict, err := engine.InspectRequest(&waf.RequestContext{
		Method:  http.MethodGet,
		Host:    "example.com",
		Path:    "/search",
		Query:   "q=1%27+OR+%271%27%3D%271",
		Headers: http.Header{},
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action == waf.ActionBlock {
		t.Fatalf("replacement pack should suppress embedded CRS, got %+v", verdict)
	}
	if v := inspectPath(t, engine, "/evil"); v.Action != waf.ActionBlock {
		t.Fatalf("replacement pack rule should still block, got %+v", v)
	}
}
