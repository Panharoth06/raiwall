package waf

import (
	"net/http"
	"strings"
	"testing"
)

type testExceptionMatcher struct {
	matchesFunc func(host, path, method, location, paramName, ruleID string) bool
}

func (m *testExceptionMatcher) Matches(host, path, method, location, paramName, ruleID string) bool {
	if m.matchesFunc != nil {
		return m.matchesFunc(host, path, method, location, paramName, ruleID)
	}
	return false
}

func TestSemanticEngine_ExceptionGate(t *testing.T) {
	matcher := &testExceptionMatcher{
		matchesFunc: func(host, path, method, location, paramName, ruleID string) bool {
			// Whitelist 'markdown_content' in POST body on /api/v1/posts for SEMANTIC_SQLI only
			if path == "/api/v1/posts" && method == "POST" && paramName == "markdown_content" && ruleID == "SEMANTIC_SQLI" {
				return true
			}
			return false
		},
	}

	eng := NewSemanticEngine(WithExceptionEngine(matcher))

	// 1. Request with exempted markdown_content containing SQLi and benign title -> Should ALLOW
	exemptCtx := &RequestContext{
		Method: "POST",
		Path:   "/api/v1/posts",
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: []byte(`{"title": "Valid Blog Post", "markdown_content": "1' OR '1'='1"}`),
	}

	verdict, err := eng.InspectRequest(exemptCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Fatalf("expected ActionAllow for exempted parameter, got %v (%s)", verdict.Action, verdict.Reason)
	}

	// 2. Request with exempted markdown_content AND malicious adjacent param 'author' -> Should BLOCK author
	maliciousAdjacentCtx := &RequestContext{
		Method: "POST",
		Path:   "/api/v1/posts",
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: []byte(`{"title": "Valid Blog Post", "author": "admin' OR 1=1--", "markdown_content": "1' OR '1'='1"}`),
	}

	verdict, err = eng.InspectRequest(maliciousAdjacentCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected ActionBlock for adjacent malicious parameter, got %v", verdict.Action)
	}
	if !strings.Contains(verdict.Reason, "author") {
		t.Errorf("expected reason to cite 'author' parameter, got %q", verdict.Reason)
	}

	// 3. Request with exempted markdown_content containing XSS (not exempt from XSS) -> Should BLOCK
	xssOnParamCtx := &RequestContext{
		Method: "POST",
		Path:   "/api/v1/posts",
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: []byte(`{"title": "Valid Blog Post", "markdown_content": "\" onerror=alert(1)"}`),
	}

	verdict, err = eng.InspectRequest(xssOnParamCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected ActionBlock for non-exempt XSS threat on markdown_content, got %v", verdict.Action)
	}
}

func TestSemanticEngine_QueryKeyInjectionDetection(t *testing.T) {
	eng := NewSemanticEngine()

	// Query string containing attack as key-only parameter (no '=' sign)
	ctx := &RequestContext{
		Method: "GET",
		Path:   "/search",
		Query:  "1%27%20OR%20%271%27%3D%271",
	}

	verdict, err := eng.InspectRequest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Errorf("SECURITY RISK: expected ActionBlock for key-only query SQLi, got %v", verdict.Action)
	}

	// Query string with attack in key alongside another valid param
	ctx2 := &RequestContext{
		Method: "GET",
		Path:   "/search",
		Query:  "page=1&UNION%20SELECT%201,2,3",
	}

	verdict2, err := eng.InspectRequest(ctx2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict2.Action != ActionBlock {
		t.Errorf("SECURITY RISK: expected ActionBlock for UNION SELECT in query, got %v", verdict2.Action)
	}
}

func TestSemanticEngine_CookieParameterException(t *testing.T) {
	matcher := &testExceptionMatcher{
		matchesFunc: func(host, path, method, location, paramName, ruleID string) bool {
			if path == "/app" && method == "GET" && (location == "Cookie" || location == "cookie") && paramName == "tracking_code" && ruleID == "SEMANTIC_SQLI" {
				return true
			}
			return false
		},
	}

	eng := NewSemanticEngine(WithExceptionEngine(matcher))

	// Request with exempted cookie containing SQLi -> Should PASS
	exemptCtx := &RequestContext{
		Method: "GET",
		Path:   "/app",
		Headers: http.Header{
			"Cookie": []string{"tracking_code=10' OR 1=1 --; session_id=safe_123"},
		},
	}
	verdict, err := eng.InspectRequest(exemptCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Fatalf("expected ActionAllow for exempted cookie, got %v (reason: %s)", verdict.Action, verdict.Reason)
	}

	// Request with attack in non-exempted cookie -> Should BLOCK
	maliciousCtx := &RequestContext{
		Method: "GET",
		Path:   "/app",
		Headers: http.Header{
			"Cookie": []string{"tracking_code=safe_val; session_id=10' OR 1=1 --"},
		},
	}
	verdict, err = eng.InspectRequest(maliciousCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected ActionBlock for adjacent malicious cookie, got %v", verdict.Action)
	}
}
