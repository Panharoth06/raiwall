//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/altcha-org/altcha-lib-go"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

func TestEndToEndBotDefense(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	// 1. Mock upstream protected backend
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","source":"api_backend"}`))
	})
	backendMux.HandleFunc("/static-page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Static Site</title></head><body><h1>Content</h1></body></html>`))
	})
	backendMux.HandleFunc("/spa-page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Next.js SPA</title></head><body><div id="__next"><div>React Content</div></div></body></html>`))
	})

	// 2. Setup Raiwall Middleware with full Bot Defense
	powSecret := "e2e-pow-verification-secret-32b"
	mw := &caddy.Middleware{
		Mode:          "defense",
		BotDefense:    "defense",
		PoWSecret:     powSecret,
		PoWDifficulty: 500, // Small difficulty for fast test execution
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	next := &e2eNextHandler{handler: backendMux}

	// -------------------------------------------------------------
	// Scenario 1: API Fast-Path (Bearer Token / /api/* / JSON Accept)
	// Must pass directly to backend without interactive challenge
	// -------------------------------------------------------------
	t.Run("API Fast Path Bypasses Challenge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		req.Header.Set("Authorization", "Bearer jwt-token-123")
		rec := httptest.NewRecorder()

		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("API request expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "api_backend") {
			t.Errorf("Backend was not reached: %s", rec.Body.String())
		}
	})

	// -------------------------------------------------------------
	// Scenario 2: Suspicious Browser Request Receives HTTP 468 PoW Challenge
	// -------------------------------------------------------------
	t.Run("Suspicious Browser Receives PoW Challenge", func(t *testing.T) {
		// Empty UA on browser route triggers suspicious classification
		req := httptest.NewRequest(http.MethodGet, "https://example.com/static-page", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		rec := httptest.NewRecorder()

		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		if rec.Code != bot.HTTPStatusChallenge {
			t.Fatalf("Expected HTTP %d PoW Challenge, got %d", bot.HTTPStatusChallenge, rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "Checking your browser") {
			t.Errorf("Challenge page missing expected verification title")
		}
		if !strings.Contains(body, "Retry verification") {
			t.Errorf("Challenge page missing retry affordance")
		}
		if !strings.Contains(body, "window.crypto.subtle.digest") {
			t.Errorf("Challenge page missing WebCrypto solver")
		}
	})

	// -------------------------------------------------------------
	// Scenario 3: Solve Challenge and Access with rw_clearance Cookie
	// -------------------------------------------------------------
	t.Run("Solve PoW Challenge and Use Clearance Cookie", func(t *testing.T) {
		clientIP := "198.51.100.42"
		ja4 := "t13d1516h2_browser_test"

		// 1. Generate challenge from engine
		ch, err := mw.PoWEngine().CreateChallenge()
		if err != nil {
			t.Fatalf("CreateChallenge failed: %v", err)
		}

		// 2. Solve challenge using Altcha solver
		sol, err := altcha.SolveChallenge(ch.Challenge, ch.Salt, altcha.SHA256, int(ch.MaxNumber), 0, nil)
		if err != nil {
			t.Fatalf("SolveChallenge failed: %v", err)
		}

		payload := altcha.Payload{
			Algorithm: ch.Algorithm,
			Challenge: ch.Challenge,
			Number:    int64(sol.Number),
			Salt:      ch.Salt,
			Signature: ch.Signature,
		}
		payloadBytes, _ := json.Marshal(payload)

		// 3. Submit solution to /.raiwall/challenge/verify
		form := url.Values{}
		form.Set("payload", string(payloadBytes))
		form.Set("redirect", "/static-page")

		verifyReq := httptest.NewRequest(http.MethodPost, bot.ChallengeVerifyPath, strings.NewReader(form.Encode()))
		verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		verifyReq.Header.Set("X-Real-IP", clientIP)
		verifyReq.Header.Set("X-JA4-Fingerprint", ja4)
		verifyRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(verifyRec, verifyReq, next); err != nil {
			t.Fatalf("ServeHTTP verify error: %v", err)
		}

		if verifyRec.Code != http.StatusSeeOther {
			t.Fatalf("Challenge verify expected status 303, got %d", verifyRec.Code)
		}

		cookies := verifyRec.Result().Cookies()
		var clearanceCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == bot.ClearanceCookieName {
				clearanceCookie = c
				break
			}
		}
		if clearanceCookie == nil {
			t.Fatalf("Expected %s cookie to be set", bot.ClearanceCookieName)
		}

		// 4. Now make request with the clearance cookie -> must pass through!
		clearedReq := httptest.NewRequest(http.MethodGet, "https://example.com/static-page", nil)
		clearedReq.Header.Set("Accept", "text/html")
		clearedReq.Header.Set("X-Real-IP", clientIP)
		clearedReq.Header.Set("X-JA4-Fingerprint", ja4)
		clearedReq.AddCookie(clearanceCookie)
		clearedRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(clearedRec, clearedReq, next); err != nil {
			t.Fatalf("ServeHTTP cleared error: %v", err)
		}

		if clearedRec.Code != http.StatusOK {
			t.Fatalf("Cleared browser request expected status 200, got %d", clearedRec.Code)
		}
	})

	// -------------------------------------------------------------
	// Scenario 4: User-Agent Spoofing (curl JA4 claiming Chrome UA)
	// Must be blocked with HTTP 403 Forbidden
	// -------------------------------------------------------------
	t.Run("User-Agent Spoofing Blocked with HTTP 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/search", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		req.Header.Set("X-JA4-Fingerprint", "t13d1516h2_curl_default") // Known cURL JA4
		rec := httptest.NewRecorder()

		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Spoofed client expected status 403, got %d", rec.Code)
		}
		if rec.Header().Get("X-Raiwall-Event-ID") == "" {
			t.Errorf("Expected X-Raiwall-Event-ID header on block")
		}
	})

	// -------------------------------------------------------------
	// Scenario 5: Honeypot Trap Visit Auto-Bans Offending Crawler
	// -------------------------------------------------------------
	t.Run("Honeypot Trap Auto-Bans Crawler", func(t *testing.T) {
		crawlerIP := "203.0.113.88"
		crawlerJA4 := "t13d1516h2_bad_crawler"

		// 1. Crawler visits honeypot trap link
		trapReq := httptest.NewRequest(http.MethodGet, "https://example.com/.raiwall/trap/crawler", nil)
		trapReq.Header.Set("X-Real-IP", crawlerIP)
		trapReq.Header.Set("X-JA4-Fingerprint", crawlerJA4)
		trapRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(trapRec, trapReq, next); err != nil {
			t.Fatalf("ServeHTTP trap error: %v", err)
		}

		if trapRec.Code != http.StatusForbidden {
			t.Fatalf("Trap hit expected status 403, got %d", trapRec.Code)
		}

		// 2. Crawler attempts any other request -> immediately blocked by auto-ban
		subsequentReq := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		subsequentReq.Header.Set("X-Real-IP", crawlerIP)
		subsequentReq.Header.Set("X-JA4-Fingerprint", crawlerJA4)
		subsequentRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(subsequentRec, subsequentReq, next); err != nil {
			t.Fatalf("ServeHTTP subsequent error: %v", err)
		}

		if subsequentRec.Code != http.StatusForbidden {
			t.Fatalf("Auto-banned client expected status 403, got %d", subsequentRec.Code)
		}
		if !strings.Contains(subsequentRec.Body.String(), "blocked due to security violations") {
			t.Errorf("Expected security ban message in response")
		}
	})

	// -------------------------------------------------------------
	// Scenario 6: Honeypot Injection on Static HTML vs SPA Hydration Safety
	// -------------------------------------------------------------
	t.Run("Static HTML Receives Honeypot but SPA Remains Untouched", func(t *testing.T) {
		clientIP := "192.0.2.1"
		token := mw.ClearanceManager().GenerateToken(net.ParseIP(clientIP), "", time.Now().Add(1*time.Hour))

		staticReq := httptest.NewRequest(http.MethodGet, "https://example.com/static-page", nil)
		staticReq.Header.Set("Accept", "text/html")
		staticReq.Header.Set("X-Real-IP", clientIP)
		staticReq.AddCookie(&http.Cookie{Name: bot.ClearanceCookieName, Value: token})
		staticRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(staticRec, staticReq, next); err != nil {
			t.Fatalf("ServeHTTP static error: %v", err)
		}

		staticBody := staticRec.Body.String()
		if !strings.Contains(staticBody, "/.raiwall/trap") {
			t.Errorf("Expected honeypot link to be injected into static HTML")
		}

		// 2. Request Next.js SPA HTML
		spaReq := httptest.NewRequest(http.MethodGet, "https://example.com/spa-page", nil)
		spaReq.Header.Set("Accept", "text/html")
		spaReq.Header.Set("X-Real-IP", clientIP)
		spaReq.AddCookie(&http.Cookie{Name: bot.ClearanceCookieName, Value: token})
		spaRec := httptest.NewRecorder()

		if err := mw.ServeHTTP(spaRec, spaReq, next); err != nil {
			t.Fatalf("ServeHTTP spa error: %v", err)
		}

		spaBody := spaRec.Body.String()
		if strings.Contains(spaBody, "/.raiwall/trap") {
			t.Errorf("Honeypot link MUST NOT be injected into SPA HTML! Hydration safety violated.")
		}
		if !strings.Contains(spaBody, `id="__next"`) {
			t.Errorf("SPA content missing")
		}
	})

	// -------------------------------------------------------------
	// Scenario 7: Concurrent Traffic with -race
	// -------------------------------------------------------------
	t.Run("Concurrent Mixed Traffic Stability", func(t *testing.T) {
		const numWorkers = 20
		const numRequests = 20
		var wg sync.WaitGroup

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for i := 0; i < numRequests; i++ {
					req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
					req.Header.Set("Authorization", "Bearer test-worker")
					rec := httptest.NewRecorder()
					_ = mw.ServeHTTP(rec, req, next)
					if rec.Code != http.StatusOK {
						t.Errorf("Worker %d request %d failed: %d", workerID, i, rec.Code)
					}
				}
			}(w)
		}

		wg.Wait()
	})
}
