package crs

import (
	"net/url"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func TestSuppressionFor(t *testing.T) {
	cases := []struct {
		name      string
		ruleID    string
		location  string
		param     string
		wantOK    bool
		directive string
	}{
		{"plain rule", "942100", "", "", true, "ctl:ruleRemoveById=942100"},
		{"crs prefix", "crs:942100", "", "", true, "ctl:ruleRemoveById=942100"},
		{"underscore prefix", "CRS_942100", "", "", true, "ctl:ruleRemoveById=942100"},
		{"pack prefix", "pack:custom:10001", "", "", true, "ctl:ruleRemoveById=10001"},
		{"query param", "942100", "query", "q", true, "ctl:ruleRemoveTargetById=942100;ARGS:q"},
		{"body param", "942100", "body", "q", true, "ctl:ruleRemoveTargetById=942100;ARGS:q"},
		{"json param", "942100", "json", "q", true, "ctl:ruleRemoveTargetById=942100;ARGS:q"},
		{"header param", "942100", "header", "X-Api-Key", true, "ctl:ruleRemoveTargetById=942100;REQUEST_HEADERS:X-Api-Key"},
		{"cookie param", "942100", "cookie", "sid", true, "ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES:sid"},
		{"unscoped param", "942100", "*", "q", true, "ctl:ruleRemoveTargetById=942100;ARGS:q"},
		{"semantic rule", "SEMANTIC_SQLI", "query", "q", false, ""},
		{"wildcard rule", "*", "query", "q", false, ""},
		{"invalid rule", "not-a-number", "", "", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SuppressionFor(tc.ruleID, tc.location, tc.param)
			if ok != tc.wantOK {
				t.Fatalf("SuppressionFor ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Directive() != tc.directive {
				t.Fatalf("directive = %q, want %q", got.Directive(), tc.directive)
			}
		})
	}
}

// TestEngine_ExceptionSuppressesMatchedRule proves a rule-level exception
// removes the offending CRS rules for the scoped request only.
func TestEngine_ExceptionSuppressesMatchedRule(t *testing.T) {
	base, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}
	query := url.Values{"q": {"1' OR '1'='1"}}.Encode()
	baseline, err := base.InspectRequest(requestContext(query))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if baseline.Action != waf.ActionBlock {
		t.Fatalf("baseline should block, got %s", baseline.Action)
	}

	var exceptions []Exception
	for _, match := range baseline.MatchedRules {
		directive, ok := SuppressionFor(match.RuleID, "", "")
		if !ok {
			continue
		}
		exceptions = append(exceptions, Exception{
			Host:       "example.com",
			PathPrefix: "/search",
			RuleID:     directive.RuleID,
		})
	}
	if len(exceptions) == 0 {
		t.Fatal("baseline did not report removable numeric rules")
	}

	engine, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1, Exceptions: exceptions})
	if err != nil {
		t.Fatalf("compile CRS with exceptions: %v", err)
	}
	verdict, err := engine.InspectRequest(requestContext(query))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionAllow {
		t.Fatalf("exception should allow the scoped request, got %s (%s)", verdict.Action, verdict.RuleID)
	}

	other := requestContext(query)
	other.Host = "other.example.com"
	verdict, err = engine.InspectRequest(other)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionBlock {
		t.Fatalf("exception must not apply to another host, got %s", verdict.Action)
	}
}

func TestEngine_TargetExceptionSuppressesParameter(t *testing.T) {
	base, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("compile CRS: %v", err)
	}
	query := url.Values{"q": {"1' OR '1'='1"}}.Encode()
	baseline, err := base.InspectRequest(requestContext(query))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if baseline.Action != waf.ActionBlock {
		t.Fatalf("baseline should block, got %s", baseline.Action)
	}

	var exceptions []Exception
	for _, match := range baseline.MatchedRules {
		directive, ok := SuppressionFor(match.RuleID, "query", "q")
		if !ok {
			continue
		}
		exceptions = append(exceptions, Exception{
			Host:      "example.com",
			Location:  "query",
			ParamName: "q",
			RuleID:    directive.RuleID,
		})
	}
	if len(exceptions) == 0 {
		t.Fatal("baseline did not report removable numeric rules")
	}

	engine, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1, Exceptions: exceptions})
	if err != nil {
		t.Fatalf("compile CRS with exceptions: %v", err)
	}
	verdict, err := engine.InspectRequest(requestContext(query))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionAllow {
		t.Fatalf("target exception should allow the parameter, got %s", verdict.Action)
	}

	otherParam := requestContext(url.Values{"other": {"1' OR '1'='1"}}.Encode())
	verdict, err = engine.InspectRequest(otherParam)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != waf.ActionBlock {
		t.Fatalf("target exception must not suppress another parameter, got %s", verdict.Action)
	}
}

func TestConfigFingerprintTracksExceptions(t *testing.T) {
	base := Config{Mode: ModeBlock, ParanoiaLevel: 1}
	withException := Config{Mode: ModeBlock, ParanoiaLevel: 1, Exceptions: []Exception{{
		Host: "example.com", RuleID: 942100,
	}}}

	if base.Fingerprint() == withException.Fingerprint() {
		t.Fatal("fingerprint must change when the exception set changes")
	}
	if base.Fingerprint() != (Config{Mode: ModeBlock, ParanoiaLevel: 1}).Fingerprint() {
		t.Fatal("fingerprint must be stable for identical configs")
	}
	if base.Fingerprint() == (Config{Mode: ModeAudit, ParanoiaLevel: 1}).Fingerprint() {
		t.Fatal("fingerprint must include enforcement mode")
	}
}

func TestEngine_RejectsInvalidExceptionRegex(t *testing.T) {
	_, err := New(Config{Mode: ModeBlock, ParanoiaLevel: 1, Exceptions: []Exception{{
		PathRegex: "([", RuleID: 942100,
	}}})
	if err == nil {
		t.Fatal("invalid exception regex must fail compilation")
	}
}
