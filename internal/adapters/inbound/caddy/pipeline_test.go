package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2"
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

func setupTestMiddleware(t *testing.T, mode string, eng waf.WAFEnginePort) *Middleware {
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
	mockEng := waf.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		return &waf.Verdict{
			Action:     waf.ActionBlock,
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
	mockEng := waf.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		return waf.VerdictAllow, nil
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
	mockEng := waf.NewMockEngine()
	// Engine identifies attack, but audit mode should NOT block!
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		return &waf.Verdict{
			Action: waf.ActionBlock,
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

func TestDynamicSnapshotModeSwitch(t *testing.T) {
	// Middleware default mode is defense
	m := setupTestMiddleware(t, "defense", waf.NewPassthroughEngine())

	app := &control.AppConfig{
		ID:        "app-test",
		Hostnames: []string{"dynamic.example.com"},
		Mode:      control.ModeOffline,
	}

	snap := control.NewConfigSnapshot(1, control.ModeDefense, []*control.AppConfig{app})
	control.StoreSnapshot(snap)

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
