package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/raiwall/raiwall/pkg/config"
	"github.com/raiwall/raiwall/pkg/engine"
)

// mockHandler implements caddyhttp.Handler for testing the middleware pipeline.
type mockHandler struct {
	served      bool
	statusCode  int
	headers     http.Header
	body        []byte
	lastRequest *http.Request
}

func newMockHandler(status int, headers http.Header, body []byte) *mockHandler {
	return &mockHandler{
		statusCode: status,
		headers:    headers,
		body:       body,
	}
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.served = true
	m.lastRequest = r
	for k, vv := range m.headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(m.statusCode)
	if len(m.body) > 0 {
		_, _ = w.Write(m.body)
	}
	return nil
}

func setupTestMiddleware(t *testing.T, mode string, eng engine.WAFEngine) *Middleware {
	m := &Middleware{
		Mode: mode,
	}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}
	if eng != nil {
		m.SetEngine(eng)
	}
	return m
}

func TestOfflineMode(t *testing.T) {
	m := setupTestMiddleware(t, "offline", nil)
	mockH := newMockHandler(http.StatusOK, nil, []byte("should not reach here"))

	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if mockH.served {
		t.Fatal("downstream handler should not have been called in offline mode")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	if !strings.Contains(rec.Body.String(), "Under Scheduled Maintenance") {
		t.Errorf("body missing maintenance message: %s", rec.Body.String())
	}
}

func TestDefenseModeBlockVerdict(t *testing.T) {
	mockEng := engine.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *engine.RequestContext) (*engine.Verdict, error) {
		return &engine.Verdict{
			Action:     engine.ActionBlock,
			RuleID:     "SQLI_RULE_942100",
			Reason:     "SQL Injection detected in URI",
			StatusCode: http.StatusForbidden,
		}, nil
	}

	m := setupTestMiddleware(t, "defense", mockEng)
	mockH := newMockHandler(http.StatusOK, nil, []byte("backend content"))

	req := httptest.NewRequest("GET", "http://example.com/search?q=1%27+OR+1=1", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if mockH.served {
		t.Fatal("downstream handler should not have been called on block verdict")
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	eventID := rec.Header().Get("X-Raiwall-Event-ID")
	if eventID == "" {
		t.Errorf("expected X-Raiwall-Event-ID header to be present")
	}

	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "Request Blocked") {
		t.Errorf("body missing 'Request Blocked': %s", bodyStr)
	}
	if !strings.Contains(bodyStr, eventID) {
		t.Errorf("body should contain rendered event ID %s", eventID)
	}
}

func TestDefenseModeAllowVerdict(t *testing.T) {
	mockEng := engine.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *engine.RequestContext) (*engine.Verdict, error) {
		return engine.VerdictAllow, nil
	}

	m := setupTestMiddleware(t, "defense", mockEng)
	mockH := newMockHandler(http.StatusOK, http.Header{"X-Upstream": {"true"}}, []byte("hello upstream"))

	req := httptest.NewRequest("GET", "http://example.com/hello", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !mockH.served {
		t.Fatal("downstream handler should have been called on allow verdict")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "hello upstream" {
		t.Errorf("body = %q, want 'hello upstream'", rec.Body.String())
	}
}

func TestAuditModeDoesNotBlock(t *testing.T) {
	mockEng := engine.NewMockEngine()
	// Engine identifies attack, but audit mode should NOT block!
	mockEng.InspectRequestHandler = func(ctx *engine.RequestContext) (*engine.Verdict, error) {
		return &engine.Verdict{
			Action: engine.ActionBlock,
			RuleID: "SQLI_RULE_942100",
		}, nil
	}

	m := setupTestMiddleware(t, "audit", mockEng)
	mockH := newMockHandler(http.StatusOK, nil, []byte("audit passed through"))

	req := httptest.NewRequest("GET", "http://example.com/search?q=attack", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !mockH.served {
		t.Fatal("downstream handler MUST be called in audit mode even if engine found threat")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestResponseInterceptorHeaderStripping(t *testing.T) {
	m := setupTestMiddleware(t, "defense", engine.NewPassthroughEngine())

	upstreamHeaders := http.Header{
		"Server":             {"Apache/2.4.41 (Ubuntu)"},
		"X-Powered-By":       {"PHP/7.4.3"},
		"X-AspNet-Version":   {"4.0.30319"},
		"Content-Type":       {"application/json"},
		"X-Custom-Safe-Head": {"safe-value"},
	}

	mockH := newMockHandler(http.StatusNotFound, upstreamHeaders, []byte(`{"error":"not found"}`))

	req := httptest.NewRequest("GET", "http://example.com/missing", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify status code captured
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// Verify stripped sensitive headers
	for _, badHeader := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if val := rec.Header().Get(badHeader); val != "" {
			t.Errorf("expected header %q to be stripped, got %q", badHeader, val)
		}
	}

	// Verify safe headers preserved
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not preserved: %v", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Custom-Safe-Head") != "safe-value" {
		t.Errorf("safe header not preserved: %v", rec.Header().Get("X-Custom-Safe-Head"))
	}
}

// flushHijackRecorder implements http.ResponseWriter, http.Flusher, and http.Hijacker.
type flushHijackRecorder struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
}

func (f *flushHijackRecorder) Flush() {
	f.flushed = true
	f.ResponseRecorder.Flush()
}

func (f *flushHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	client, server := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestResponseInterceptorFlusherAndHijacker(t *testing.T) {
	rec := &flushHijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	interceptor := NewResponseInterceptor(rec, DefaultSensitiveHeaders)

	// Test Flush delegation
	interceptor.Flush()
	if !rec.flushed {
		t.Errorf("expected Flush() to be delegated to underlying recorder")
	}

	// Test Hijack delegation
	conn, rw, err := interceptor.Hijack()
	if err != nil {
		t.Fatalf("unexpected Hijack error: %v", err)
	}
	if !rec.hijacked {
		t.Errorf("expected Hijack() to be delegated")
	}
	if conn != nil {
		_ = conn.Close()
	}
	_ = rw
}

func TestDynamicSnapshotModeSwitch(t *testing.T) {
	// Middleware default mode is defense
	m := setupTestMiddleware(t, "defense", engine.NewPassthroughEngine())

	app := &config.AppConfig{
		ID:        "app-test",
		Hostnames: []string{"dynamic.example.com"},
		Mode:      config.ModeOffline,
	}

	snap := config.NewConfigSnapshot(1, config.ModeDefense, []*config.AppConfig{app})
	config.StoreSnapshot(snap)

	// Request for dynamic.example.com should be resolved to Offline mode
	mockH := newMockHandler(http.StatusOK, nil, []byte("should be blocked"))
	req := httptest.NewRequest("GET", "http://dynamic.example.com/test", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if mockH.served {
		t.Fatal("dynamic app offline mode should have halted request")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for dynamic offline app, got %d", rec.Code)
	}

	// Request for other host falls back to defense
	mockH2 := newMockHandler(http.StatusOK, nil, []byte("allowed for other"))
	req2 := httptest.NewRequest("GET", "http://other.example.com/test", nil)
	rec2 := httptest.NewRecorder()

	err = m.ServeHTTP(rec2, req2, mockH2)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if !mockH2.served {
		t.Fatal("other host should be allowed under defense mode")
	}
}

func TestResponseInterceptorInformational1xx(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := NewResponseInterceptor(rec, []string{"Server", "X-Powered-By"})

	// 1. Send 103 Early Hints with a Link header and sensitive header
	interceptor.Header().Set("Link", "</style.css>; rel=preload; as=style")
	interceptor.Header().Set("Server", "Backend/1.0")
	interceptor.WriteHeader(http.StatusEarlyHints)

	if interceptor.StatusCode() != http.StatusEarlyHints {
		t.Errorf("interceptor status after 103 = %d, want 103", interceptor.StatusCode())
	}

	// 2. Now send final 200 OK with body and more headers
	interceptor.Header().Set("X-Custom", "active")
	interceptor.WriteHeader(http.StatusOK)
	_, _ = interceptor.Write([]byte("final body"))

	if interceptor.StatusCode() != http.StatusOK {
		t.Errorf("final interceptor status = %d, want 200", interceptor.StatusCode())
	}
	if rec.Header().Get("Server") != "" {
		t.Errorf("Server header was not stripped on 200 OK: %s", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Custom") != "active" {
		t.Errorf("X-Custom header missing on 200 OK")
	}
	if rec.Body.String() != "final body" {
		t.Errorf("body = %q, want 'final body'", rec.Body.String())
	}
}

func TestChunkedRequestBodyInspection(t *testing.T) {
	var inspectedBody string
	mockEng := engine.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *engine.RequestContext) (*engine.Verdict, error) {
		inspectedBody = string(ctx.Body)
		if strings.Contains(inspectedBody, "union select") {
			return &engine.Verdict{
				Action:     engine.ActionBlock,
				RuleID:     "SQLI_CHUNKED",
				Reason:     "SQL injection detected in chunked body",
				StatusCode: http.StatusForbidden,
			}, nil
		}
		return engine.VerdictAllow, nil
	}

	m := setupTestMiddleware(t, "defense", mockEng)

	// Test 1: Chunked request containing threat (ContentLength == -1)
	chunkedPayload := "param=val&query=union select 1,2,3"
	reqThreat := httptest.NewRequest("POST", "http://example.com/api", io.NopCloser(strings.NewReader(chunkedPayload)))
	reqThreat.ContentLength = -1 // simulate chunked encoding without Content-Length
	recThreat := httptest.NewRecorder()

	mockH := newMockHandler(http.StatusOK, nil, []byte("backend"))
	err := m.ServeHTTP(recThreat, reqThreat, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if mockH.served {
		t.Fatal("backend handler should NOT have been called for malicious chunked request")
	}
	if recThreat.Code != http.StatusForbidden {
		t.Errorf("expected 403 on malicious chunked request, got %d", recThreat.Code)
	}
	if inspectedBody != chunkedPayload {
		t.Errorf("inspected body = %q, want %q", inspectedBody, chunkedPayload)
	}

	// Test 2: Safe chunked request passes through and downstream handler can read full body
	safePayload := "param=val&query=safe"
	reqSafe := httptest.NewRequest("POST", "http://example.com/api", io.NopCloser(strings.NewReader(safePayload)))
	reqSafe.ContentLength = -1
	recSafe := httptest.NewRecorder()

	var downstreamReceivedBody string
	safeH := newMockHandler(http.StatusOK, nil, []byte("ok"))
	// Override mockHandler to read request body
	safeCustomH := &safeBodyReadHandler{
		handler: safeH,
		onRead: func(b []byte) {
			downstreamReceivedBody = string(b)
		},
	}

	err = m.ServeHTTP(recSafe, reqSafe, safeCustomH)
	if err != nil {
		t.Fatalf("ServeHTTP error on safe chunked: %v", err)
	}
	if recSafe.Code != http.StatusOK {
		t.Errorf("expected 200 on safe chunked, got %d", recSafe.Code)
	}
	if downstreamReceivedBody != safePayload {
		t.Errorf("downstream received body = %q, want %q", downstreamReceivedBody, safePayload)
	}
}

type safeBodyReadHandler struct {
	handler *mockHandler
	onRead  func([]byte)
}

func (s *safeBodyReadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	b, _ := io.ReadAll(r.Body)
	if s.onRead != nil {
		s.onRead(b)
	}
	return s.handler.ServeHTTP(w, r)
}

func TestMiddlewareValidate(t *testing.T) {
	m := &Middleware{
		runMode:           config.ModeDefense,
		BlockStatusCode:   403,
		OfflineStatusCode: 503,
	}
	if err := m.Validate(); err != nil {
		t.Errorf("expected valid middleware, got err: %v", err)
	}

	// Invalid run mode
	mBadMode := &Middleware{
		runMode: "bad",
	}
	if err := mBadMode.Validate(); err == nil {
		t.Error("expected error for invalid run mode")
	}

	// Invalid block status code
	mBadBlock := &Middleware{
		runMode:         config.ModeDefense,
		BlockStatusCode: 700,
	}
	if err := mBadBlock.Validate(); err == nil {
		t.Error("expected error for block status code 700")
	}

	// Invalid offline status code
	mBadOffline := &Middleware{
		runMode:           config.ModeDefense,
		OfflineStatusCode: 150,
	}
	if err := mBadOffline.Validate(); err == nil {
		t.Error("expected error for offline status code 150")
	}
}

