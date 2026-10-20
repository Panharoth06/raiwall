package acl

import (
	"sync"
	"testing"
)

func TestExceptionEngine_LifecycleAndConcurrency(t *testing.T) {
	rule1 := &ExceptionRule{
		ID:         "rule-1",
		PathPrefix: "/api/safe",
		ParamName:  "content",
		RuleID:     "SEMANTIC_SQLI",
	}
	rule2 := &ExceptionRule{
		ID:        "rule-2",
		PathRegex: `^/api/v2/.*$`,
		RuleID:    "*",
	}

	engine, err := NewExceptionEngine(rule1, rule2)
	if err != nil {
		t.Fatalf("NewExceptionEngine error: %v", err)
	}

	if len(engine.Rules()) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(engine.Rules()))
	}

	// Test matches
	if !engine.Matches("example.com", "/api/safe/post", "POST", "Body", "content", "SEMANTIC_SQLI") {
		t.Errorf("expected rule-1 to match")
	}
	// Different param shouldn't match rule1
	if engine.Matches("example.com", "/api/safe/post", "POST", "Body", "other", "SEMANTIC_SQLI") {
		t.Errorf("expected rule-1 NOT to match other param")
	}

	// Test update existing rule
	updatedRule1 := &ExceptionRule{
		ID:         "rule-1",
		PathPrefix: "/api/safe",
		ParamName:  "content",
		RuleID:     "*", // upgraded to all rules
	}
	if err := engine.AddRule(updatedRule1); err != nil {
		t.Fatalf("AddRule error: %v", err)
	}
	if len(engine.Rules()) != 2 {
		t.Fatalf("expected still 2 rules after update, got %d", len(engine.Rules()))
	}
	if !engine.Matches("example.com", "/api/safe/post", "POST", "Body", "content", "SEMANTIC_XSS") {
		t.Errorf("expected updated rule-1 to match SEMANTIC_XSS")
	}

	// Concurrent read and writes
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = engine.Matches("example.com", "/api/safe/post", "POST", "Body", "content", "SEMANTIC_SQLI")
			_ = engine.MatchingRules("example.com", "/api/v2/test", "GET", "Query", "q", "SEMANTIC_SQLI")
		}(i)
		go func(idx int) {
			defer wg.Done()
			r := &ExceptionRule{
				ID:        "dynamic",
				PathRegex: `^/dyn/.*$`,
			}
			_ = engine.AddRule(r)
		}(i)
	}
	wg.Wait()

	// Test remove rule
	if !engine.RemoveRule("rule-1") {
		t.Errorf("expected rule-1 to be removed")
	}
	if engine.RemoveRule("non-existent") {
		t.Errorf("expected non-existent rule removal to return false")
	}

	engine.ClearRules()
	if len(engine.Rules()) != 0 {
		t.Errorf("expected 0 rules after ClearRules, got %d", len(engine.Rules()))
	}
}

func TestExceptionRule_IPv6AndCookieMatching(t *testing.T) {
	ruleIPv6 := &ExceptionRule{
		ID:        "ipv6-rule",
		Host:      "[2001:db8::1]",
		Location:  "body",
		ParamName: "data",
	}
	if err := ruleIPv6.Compile(); err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	// Should match with or without port and with or without brackets
	if !ruleIPv6.Matches("[2001:db8::1]:8080", "/submit", "POST", "body", "data", "SEMANTIC_SQLI") {
		t.Errorf("expected match for bracketed IPv6 with port")
	}
	if !ruleIPv6.Matches("2001:db8::1", "/submit", "POST", "body", "data", "SEMANTIC_SQLI") {
		t.Errorf("expected match for raw IPv6")
	}
	if ruleIPv6.Matches("[2001:db8::2]:8080", "/submit", "POST", "body", "data", "SEMANTIC_SQLI") {
		t.Errorf("expected no match for different IPv6")
	}

	// Cookie location matching
	ruleCookie := &ExceptionRule{
		ID:        "cookie-rule",
		Location:  "cookie",
		ParamName: "session_id",
	}
	if err := ruleCookie.Compile(); err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	// Should match when reported as Cookie location
	if !ruleCookie.Matches("example.com", "/", "GET", "Cookie", "session_id", "SEMANTIC_SQLI") {
		t.Errorf("expected match for Cookie location")
	}
	// Should also match when reported under Header location
	if !ruleCookie.Matches("example.com", "/", "GET", "Header", "session_id", "SEMANTIC_SQLI") {
		t.Errorf("expected match for Header location when rule targets cookie")
	}
}
