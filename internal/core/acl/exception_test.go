package acl

import (
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
			name: "header location matches cookie parameter",
			rule: ExceptionRule{
				Location:  "Header",
				ParamName: "Cookie",
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
			name: "header location matches cookie parameter",
			rule: ExceptionRule{
				Location:  "Header",
				ParamName: "session_id",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Cookie",
			paramName: "session_id",
			ruleID:    "SEMANTIC_SQLI",
			wantMatch: true,
		},
		{
			name: "cookie location with case-insensitive param name",
			rule: ExceptionRule{
				Location:  "Cookie",
				ParamName: "Session_Id",
			},
			host:      "example.com",
			path:      "/",
			method:    "GET",
			location:  "Cookie",
			paramName: "session_id",
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
