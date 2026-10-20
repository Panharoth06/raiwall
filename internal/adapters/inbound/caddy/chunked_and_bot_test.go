package caddy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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

func TestChunkedRequestBodyInspection(t *testing.T) {
	var inspectedBody string
	mockEng := waf.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		inspectedBody = string(ctx.Body)
		if strings.Contains(inspectedBody, "union select") {
			return &waf.Verdict{
				Action:     waf.ActionBlock,
				RuleID:     "SQLI_CHUNKED",
				Reason:     "SQL injection detected in chunked body",
				StatusCode: http.StatusForbidden,
			}, nil
		}
		return waf.VerdictAllow, nil
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

func TestMiddlewareValidate(t *testing.T) {
	m := &Middleware{
		runMode:           control.ModeDefense,
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
		runMode:         control.ModeDefense,
		BlockStatusCode: 700,
	}
	if err := mBadBlock.Validate(); err == nil {
		t.Error("expected error for block status code 700")
	}

	// Invalid offline status code
	mBadOffline := &Middleware{
		runMode:           control.ModeDefense,
		OfflineStatusCode: 150,
	}
	if err := mBadOffline.Validate(); err == nil {
		t.Error("expected error for offline status code 150")
	}

	// Invalid bot_defense mode
	mBadBot := &Middleware{
		runMode:    control.ModeDefense,
		BotDefense: "invalid_defense",
	}
	if err := mBadBot.Validate(); err == nil {
		t.Error("expected error for invalid bot_defense")
	}

	// Invalid pow_difficulty
	mBadDiff := &Middleware{
		runMode:       control.ModeDefense,
		PoWDifficulty: -10,
	}
	if err := mBadDiff.Validate(); err == nil {
		t.Error("expected error for negative pow_difficulty")
	}
}

func TestBotDefense_AuditModeDoesNotBlock(t *testing.T) {
	m := &Middleware{
		Mode:       "defense",
		BotDefense: "audit",
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision error: %v", err)
	}

	// Request with curl JA4 claiming to be Chrome UA (spoofed)
	req := httptest.NewRequest("GET", "https://example.com/page", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("X-JA4-Fingerprint", "t13d1516h2_curl_default")
	rec := httptest.NewRecorder()

	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend passed"))
		return nil
	})

	err := m.ServeHTTP(rec, req, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// In audit mode, request MUST NOT be blocked (code 200, reached backend)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK in audit mode, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "backend passed") {
		t.Errorf("Backend was not reached in audit mode: %s", rec.Body.String())
	}
}
