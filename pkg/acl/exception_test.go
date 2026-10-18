package acl

import (
	"sync"
	"testing"
)

func TestExceptionRule_Matches(t *testing.T) {
	tests := []struct {
		name      string
		rule      ExceptionRule
		host      string
		path      string
		method    string
		location  string
		paramName string
		ruleID    string
		wantMatch bool
	}{
		{
			name: "exact host, path prefix, method, location, param, rule",
			rule: ExceptionRule{
				Host:       "example.com",
				PathPrefix: "/api/v1/posts",
				Method:     "POST",
				Location:   "Body",
				ParamName:  "markdown_content",
				RuleID:     "SEMANTIC_SQLI",
			},
			host:      "example.com",
			path:      "/api/v1/posts/submit",
			method:    "POST",
			location:  "Body",
			paramName: "markdown_content",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: true,
		},
		{
			name: "wildcard host and ruleID",
			rule: ExceptionRule{
				Host:       "*",
				PathPrefix: "/search",
				Method:     "*",
				Location:   "Query",
				ParamName:  "q",
				RuleID:     "*",
			},
			host:      "sub.domain.org:8080",
			path:      "/search",
			method:    "GET",
			location:  "Query",
			paramName: "q",
			ruleID:    "SEMANTIC_XSS",
			wantMatch: true,
		},
		{
			name: "subdomain wildcard host",
			rule: ExceptionRule{
				Host:       "*.example.com",
				PathPrefix: "/admin",
				RuleID:     "SEMANTIC_CMDI",
			},
			host:      "app.example.com",
			path:      "/admin/dashboard",
			method:    "GET",
			location:  "Query",
			paramName: "cmd",
			ruleID:    "SEMANTIC_CMDI",
			wantMatch: true,
		},
		{
			name: "subdomain wildcard mismatch",
			rule: ExceptionRule{
				Host:       "*.example.com",
				PathPrefix: "/admin",
			},
			host:      "notexample.com",
			path:      "/admin/dashboard",
			method:    "GET",
			location:  "Query",
			paramName: "cmd",
			ruleID:    "SEMANTIC_CMDI",
			wantMatch: false,
		},
		{
			name: "regex path match",
			rule: ExceptionRule{
				PathRegex: `^/users/\d+/profile$`,
				Location:  "JSON",
				ParamName: "bio",
			},
			host:      "example.com",
			path:      "/users/12345/profile",
			method:    "PUT",
			location:  "JSON",
			paramName: "bio",
			ruleID:    "SEMANTIC_XSS",
			wantMatch: true,
		},
		{
			name: "regex path mismatch",
			rule: ExceptionRule{
				PathRegex: `^/users/\d+/profile$`,
				Location:  "JSON",
				ParamName: "bio",
			},
			host:      "example.com",
			path:      "/users/abc/profile",
			method:    "PUT",
			location:  "JSON",
			paramName: "bio",
			ruleID:    "SEMANTIC_XSS",
			wantMatch: false,
		},
		{
			name: "regex param name match",
			rule: ExceptionRule{
				PathPrefix: "/upload",
				ParamRegex: `^custom_field_\d+$`,
			},
			host:      "example.com",
			path:      "/upload",
			method:    "POST",
			location:  "Multipart",
			paramName: "custom_field_42",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: true,
		},
		{
			name: "cookie location via header matching",
			rule: ExceptionRule{
				Location:  "Cookie",
				ParamName: "session",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Cookie",
			paramName: "session",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: true,
		},
		{
			name: "cookie mapped to header with cookie name",
			rule: ExceptionRule{
				Location: "Cookie",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Header",
			paramName: "Cookie",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: true,
		},
		{
			name: "method mismatch",
			rule: ExceptionRule{
				Method: "POST",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Query",
			paramName: "foo",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: false,
		},
		{
			name: "rule ID mismatch",
			rule: ExceptionRule{
				RuleID: "SEMANTIC_SQLI",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Query",
			paramName: "foo",
			ruleID:    "SEMANTIC_XSS",
			wantMatch: false,
		},
		{
			name: "location mismatch",
			rule: ExceptionRule{
				Location: "Header",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Body",
			paramName: "foo",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: false,
		},
		{
			name: "param name mismatch",
			rule: ExceptionRule{
				ParamName: "safe_field",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Body",
			paramName: "malicious_field",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rule.Compile(); err != nil {
				t.Fatalf("Compile() failed: %v", err)
			}
			got := tt.rule.Matches(tt.host, tt.path, tt.method, tt.location, tt.paramName, tt.ruleID)
			if got != tt.wantMatch {
				t.Errorf("Matches() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

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
