package rate

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
)

func TestTier1VelocityLimiter(t *testing.T) {
	powEngine := bot.NewPoWEngine(bot.PoWConfig{
		Secret:     "tier1-test-secret-32-bytes-long!",
		Difficulty: 100,
	})

	cfg := Tier1Config{
		Rate:       2,
		Period:     time.Second,
		Burst:      0, // strictly 1 allowed at t=0
		CookieName: "session",
		PoWEngine:  powEngine,
	}

	limiter := NewTier1VelocityLimiter(cfg)
	defer limiter.Close()

	ip := net.ParseIP("198.51.100.1")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"

	t.Run("Browser route receives HTTP 468 challenge on limit trip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/home", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")

		// 1st request -> allowed
		rec1 := httptest.NewRecorder()
		allowed, err := limiter.Enforce(rec1, req, ip, ja4)
		if err != nil || !allowed {
			t.Fatalf("1st request should be allowed: %v", err)
		}

		// 2nd request at t=0 -> rate limit exceeded -> HTTP 468 PoW challenge
		rec2 := httptest.NewRecorder()
		allowed, err = limiter.Enforce(rec2, req, ip, ja4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("2nd request should be blocked/challenged")
		}

		if rec2.Code != bot.HTTPStatusChallenge {
			t.Errorf("expected HTTP status 468, got %d", rec2.Code)
		}
		if !strings.Contains(rec2.Body.String(), "Verifying Connection") && !strings.Contains(rec2.Body.String(), "Raiwall Gateway Defense") {
			t.Errorf("expected PoW challenge HTML body, got: %s", rec2.Body.String())
		}
	})

	t.Run("API route receives HTTP 429 JSON on limit trip (/api/*)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/items", nil)
		apiIP := net.ParseIP("198.51.100.2")

		// 1st request -> allowed
		rec1 := httptest.NewRecorder()
		allowed, err := limiter.Enforce(rec1, req, apiIP, ja4)
		if err != nil || !allowed {
			t.Fatalf("1st API request should be allowed: %v", err)
		}

		// 2nd request -> HTTP 429
		rec2 := httptest.NewRecorder()
		allowed, err = limiter.Enforce(rec2, req, apiIP, ja4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("2nd API request should be rate limited")
		}

		if rec2.Code != http.StatusTooManyRequests {
			t.Errorf("expected HTTP status 429, got %d", rec2.Code)
		}
		if rec2.Header().Get("Retry-After") == "" {
			t.Errorf("expected Retry-After header on 429 response")
		}

		var apiErr Tier1APIErrorResponse
		if err := json.Unmarshal(rec2.Body.Bytes(), &apiErr); err != nil {
			t.Fatalf("failed to decode JSON error response: %v", err)
		}
		if apiErr.Error != "rate_limit_exceeded" {
			t.Errorf("unexpected error code in JSON: %s", apiErr.Error)
		}
		if apiErr.RetryAfter <= 0 {
			t.Errorf("expected positive retry_after in JSON, got %d", apiErr.RetryAfter)
		}
	})

	t.Run("Bearer token route receives HTTP 429 JSON on limit trip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/webhook", nil)
		req.Header.Set("Authorization", "Bearer sk_test_token_abc")
		bearerIP := net.ParseIP("198.51.100.3")

		// 1st request -> allowed
		rec1 := httptest.NewRecorder()
		allowed, err := limiter.Enforce(rec1, req, bearerIP, ja4)
		if err != nil || !allowed {
			t.Fatalf("1st Bearer request should be allowed: %v", err)
		}

		// 2nd request -> HTTP 429
		rec2 := httptest.NewRecorder()
		allowed, err = limiter.Enforce(rec2, req, bearerIP, ja4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("2nd Bearer request should be rate limited")
		}

		if rec2.Code != http.StatusTooManyRequests {
			t.Errorf("expected HTTP 429 for Bearer token request, got %d", rec2.Code)
		}
	})

	t.Run("Composite key isolation between users on same IP", func(t *testing.T) {
		sharedIP := net.ParseIP("203.0.113.50")

		reqA := httptest.NewRequest(http.MethodGet, "https://example.com/api/test", nil)
		reqA.AddCookie(&http.Cookie{Name: "session", Value: "session-alice"})

		reqB := httptest.NewRequest(http.MethodGet, "https://example.com/api/test", nil)
		reqB.AddCookie(&http.Cookie{Name: "session", Value: "session-bob"})

		// User A uses up their limit
		recA1 := httptest.NewRecorder()
		allowedA1, _ := limiter.Enforce(recA1, reqA, sharedIP, ja4)
		if !allowedA1 {
			t.Fatalf("Alice's 1st request should be allowed")
		}

		recA2 := httptest.NewRecorder()
		allowedA2, _ := limiter.Enforce(recA2, reqA, sharedIP, ja4)
		if allowedA2 {
			t.Fatalf("Alice's 2nd request should be blocked")
		}

		// User B on the same IP must NOT be blocked!
		recB1 := httptest.NewRecorder()
		allowedB1, err := limiter.Enforce(recB1, reqB, sharedIP, ja4)
		if err != nil || !allowedB1 {
			t.Fatalf("Bob should be allowed despite Alice being rate limited on same IP: %v", err)
		}
	})

	t.Run("Verified browser receives HTTP 429 rather than infinite PoW challenge", func(t *testing.T) {
		clearanceMgr := bot.NewClearanceManager(bot.ClearanceConfig{
			Secret: "test-secret-32-bytes-tier1-clear",
			TTL:    1 * time.Hour,
		}, powEngine)
		limiter.SetClearanceManager(clearanceMgr)

		verifiedIP := net.ParseIP("198.51.100.99")
		token := clearanceMgr.GenerateToken(verifiedIP, ja4, time.Now().Add(1*time.Hour))

		req := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(&http.Cookie{Name: bot.ClearanceCookieName, Value: token})

		// 1st request -> allowed
		rec1 := httptest.NewRecorder()
		allowed1, _ := limiter.Enforce(rec1, req, verifiedIP, ja4)
		if !allowed1 {
			t.Fatalf("1st request for verified browser should be allowed")
		}

		// 2nd request -> exceeds rate limit
		rec2 := httptest.NewRecorder()
		allowed2, _ := limiter.Enforce(rec2, req, verifiedIP, ja4)
		if allowed2 {
			t.Fatalf("2nd request should be rate limited")
		}

		// Must receive HTTP 429 Too Many Requests, NOT HTTP 468 challenge
		if rec2.Code != http.StatusTooManyRequests {
			t.Errorf("verified browser exceeding velocity expected HTTP 429, got %d", rec2.Code)
		}
		if rec2.Header().Get("Retry-After") == "" {
			t.Errorf("expected Retry-After header on 429")
		}
	})
}
