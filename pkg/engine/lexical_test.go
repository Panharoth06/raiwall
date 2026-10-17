package engine

import (
	"net/http"
	"testing"
)

func TestLexicalEngineSQLiDetection(t *testing.T) {
	eng := NewLexicalEngine()
	if eng.Name() != "libinjection-go" {
		t.Fatalf("expected name 'libinjection-go', got %q", eng.Name())
	}

	tests := []struct {
		name        string
		ctx         *RequestContext
		expectBlock bool
		expectRule  string
	}{
		{
			name: "Benign request",
			ctx: &RequestContext{
				Path:   "/api/products",
				Query:  "category=shoes&sort=asc",
				Method: "GET",
			},
			expectBlock: false,
		},
		{
			name: "SQLi in query parameter",
			ctx: &RequestContext{
				Path:   "/api/users",
				Query:  "id=1%27+OR+%271%27%3D%271",
				Method: "GET",
			},
			expectBlock: true,
			expectRule:  "SQLI_QUERY_PARAM",
		},
		{
			name: "SQLi in raw Query",
			ctx: &RequestContext{
				Path:   "/search",
				Query:  "-1 UNION SELECT 1,2,password FROM users",
				Method: "GET",
			},
			expectBlock: true,
			expectRule:  "SQLI_QUERY",
		},
		{
			name: "SQLi in Cookie Header",
			ctx: &RequestContext{
				Path:   "/dashboard",
				Method: "GET",
				Headers: http.Header{
					"Cookie": []string{"session=123; tracking=1' UNION SELECT 1,version()--"},
				},
			},
			expectBlock: true,
			expectRule:  "SQLI_HEADER",
		},
		{
			name: "SQLi in Body",
			ctx: &RequestContext{
				Path:   "/login",
				Method: "POST",
				Body:   []byte(`admin' --`),
			},
			expectBlock: true,
			expectRule:  "SQLI_BODY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tt.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectBlock {
				if verdict.Action != ActionBlock {
					t.Fatalf("expected ActionBlock, got %v", verdict.Action)
				}
				if verdict.RuleID != tt.expectRule {
					t.Errorf("expected RuleID %q, got %q", tt.expectRule, verdict.RuleID)
				}
			} else {
				if verdict.Action != ActionAllow {
					t.Fatalf("expected ActionAllow, got %v", verdict.Action)
				}
			}
		})
	}
}

func TestLexicalEngineXSSDetection(t *testing.T) {
	eng := NewLexicalEngine()

	tests := []struct {
		name        string
		ctx         *RequestContext
		expectBlock bool
		expectRule  string
	}{
		{
			name: "Benign input",
			ctx: &RequestContext{
				Path:  "/comment",
				Query: "msg=Hello+world%21",
			},
			expectBlock: false,
		},
		{
			name: "XSS in Query Param",
			ctx: &RequestContext{
				Path:  "/search",
				Query: "q=%3Cscript%3Ealert(1)%3C/script%3E",
			},
			expectBlock: true,
			expectRule:  "XSS_QUERY_PARAM",
		},
		{
			name: "XSS in Body",
			ctx: &RequestContext{
				Path: "/submit",
				Body: []byte(`<img src=x onerror=alert('XSS')>`),
			},
			expectBlock: true,
			expectRule:  "XSS_BODY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tt.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectBlock {
				if verdict.Action != ActionBlock {
					t.Fatalf("expected ActionBlock, got %v", verdict.Action)
				}
				if verdict.RuleID != tt.expectRule {
					t.Errorf("expected RuleID %q, got %q", tt.expectRule, verdict.RuleID)
				}
			} else {
				if verdict.Action != ActionAllow {
					t.Fatalf("expected ActionAllow, got %v", verdict.Action)
				}
			}
		})
	}
}
