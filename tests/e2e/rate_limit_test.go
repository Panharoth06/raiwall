//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

type rateLimitFixture struct {
	mw        *caddy.Middleware
	next      *e2eNextHandler
	powSecret string
}

func setupRateLimitFixture(t *testing.T) *rateLimitFixture {
	t.Helper()

	control.StoreSnapshot(control.NewConfigSnapshot(200, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	backendMux := http.NewServeMux()
	var backendRequests atomic.Int64
	backendMux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","source":"api_service"}`))
	})
	backendMux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Dashboard</h1></body></html>`))
	})
	backendMux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`slow response`))
	})

	powSecret := "e2e-rate-limit-secret-32-bytes"
	mw := &caddy.Middleware{
		Mode:          "defense",
		BotDefense:    "defense",
		PoWSecret:     powSecret,
		PoWDifficulty: 200,
		RateLimitConfig: &caddy.RateLimitSettings{
			Tier1Rate:        10,
			Tier1Period:      caddyv2.Duration(time.Second),
			Tier1Burst:       5,
			Tier2Threshold:   3,
			Tier2Window:      caddyv2.Duration(time.Second),
			Tier2BanDuration: caddyv2.Duration(1 * time.Hour),
			Tier3Threshold:   3,
			Tier3Window:      caddyv2.Duration(time.Second),
			Tier3BanDuration: caddyv2.Duration(1 * time.Hour),
			StorageType:      "memory",
		},
		WaitingRoomConfig: &caddy.WaitingRoomSettings{
			Enabled:               true,
			MaxConcurrentInFlight: 3,
			MaxQueueDepth:         4,
			AdmissionRate:         10,
			AdmissionTokenTTL:     caddyv2.Duration(15 * time.Minute),
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	return &rateLimitFixture{
		mw:        mw,
		next:      &e2eNextHandler{handler: backendMux},
		powSecret: powSecret,
	}
}

func TestEndToEndRateLimitAndDDoSDefense(t *testing.T) {
	f := setupRateLimitFixture(t)

	// Scenario 1: Tier 1 Flood - Browser Receives PoW, API Receives 429
	t.Run("Tier 1 Flood: Browser PoW vs API 429", func(t *testing.T) {
		browserIP := "198.51.100.10"
		apiIP := "198.51.100.20"
		ja4 := "t13d1516h2_8daaf6152771_0123456789ab"

		var gotChallenge bool
		for i := 0; i < 8; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
			req.Header.Set("X-Real-IP", browserIP)
			req.Header.Set("X-JA4-Fingerprint", ja4)
			rec := httptest.NewRecorder()

			if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
				t.Fatalf("ServeHTTP error: %v", err)
			}
			if rec.Code == bot.HTTPStatusChallenge {
				gotChallenge = true
				if !strings.Contains(rec.Body.String(), "Verifying Connection") {
					t.Errorf("expected PoW challenge HTML body, got: %s", rec.Body.String())
				}
				break
			}
		}
		if !gotChallenge {
			t.Errorf("browser flood should have triggered HTTP 468 PoW challenge")
		}

		var got429 bool
		for i := 0; i < 8; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
			req.Header.Set("Authorization", "Bearer sk_api_token_123")
			req.Header.Set("X-Real-IP", apiIP)
			req.Header.Set("X-JA4-Fingerprint", ja4)
			rec := httptest.NewRecorder()

			if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
				t.Fatalf("ServeHTTP error: %v", err)
			}
			if rec.Code == http.StatusTooManyRequests {
				got429 = true
				if rec.Header().Get("Retry-After") == "" {
					t.Errorf("API 429 response missing Retry-After header")
				}
				var apiErr rate.Tier1APIErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil {
					t.Fatalf("invalid JSON error response: %v", err)
				}
				if apiErr.Error != "rate_limit_exceeded" {
					t.Errorf("unexpected error in JSON: %s", apiErr.Error)
				}
				break
			}
		}
		if !got429 {
			t.Errorf("API flood should have triggered HTTP 429 Too Many Requests")
		}
	})

	// Scenario 2: Tier 2 Repeated Attack Auto-Ban
	t.Run("Tier 2 Repeated Attacks Trigger Auto-Ban", func(t *testing.T) {
		attackerIP := "198.51.100.66"
		attackerJA4 := "t13d1516h2_attacker_signature"

		for i := 0; i < 4; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data?q=1%27%20OR%20%271%27=%271", nil)
			req.Header.Set("Authorization", "Bearer token-attacker")
			req.Header.Set("X-Real-IP", attackerIP)
			req.Header.Set("X-JA4-Fingerprint", attackerJA4)
			rec := httptest.NewRecorder()

			_ = f.mw.ServeHTTP(rec, req, f.next)
			if rec.Code != http.StatusForbidden {
				t.Errorf("attack %d expected 403, got %d", i+1, rec.Code)
			}
		}

		ipParsed := net.ParseIP(attackerIP)
		isBanned, entry := f.mw.BanManager().IsBanned(ipParsed, attackerJA4)
		if !isBanned || entry == nil {
			t.Fatalf("expected attacker to be auto-banned in BanManager after repeated attacks")
		}

		benignReq := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		benignReq.Header.Set("Authorization", "Bearer token-attacker")
		benignReq.Header.Set("X-Real-IP", attackerIP)
		benignReq.Header.Set("X-JA4-Fingerprint", attackerJA4)
		recBenign := httptest.NewRecorder()

		if err := f.mw.ServeHTTP(recBenign, benignReq, f.next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if recBenign.Code != http.StatusForbidden {
			t.Errorf("banned client benign request expected 403, got %d", recBenign.Code)
		}
	})

	// Scenario 3: Tier 3 Scanner Trap with Anti-CGNAT Protection
	t.Run("Tier 3 Scanner Trap Neutralization with Anti-CGNAT", func(t *testing.T) {
		sharedIP := "203.0.113.111"
		scannerJA4 := "t13d1516h2_scanner_ffuf"
		innocentJA4 := "t13d1516h2_innocent_browser"

		fuzzTargets := []string{
			"/api/secret_env",
			"/api/config_bak",
			"/api/admin_keys",
			"/api/server_status",
		}

		for _, path := range fuzzTargets {
			req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
			req.Header.Set("Authorization", "Bearer scanner-recon")
			req.Header.Set("X-Real-IP", sharedIP)
			req.Header.Set("X-JA4-Fingerprint", scannerJA4)
			rec := httptest.NewRecorder()

			_ = f.mw.ServeHTTP(rec, req, f.next)
		}

		ipParsed := net.ParseIP(sharedIP)
		isScannerBanned, _ := f.mw.BanManager().IsBanned(ipParsed, scannerJA4)
		if !isScannerBanned {
			t.Fatalf("expected scanner to be auto-banned after reconnaissance flood")
		}

		isInnocentBanned, _ := f.mw.BanManager().IsBanned(ipParsed, innocentJA4)
		if isInnocentBanned {
			t.Fatalf("innocent user sharing CGNAT IP must NOT be banned when scanner is banned!")
		}

		innocentReq := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		innocentReq.Header.Set("Authorization", "Bearer jwt-innocent")
		innocentReq.Header.Set("X-Real-IP", sharedIP)
		innocentReq.Header.Set("X-JA4-Fingerprint", innocentJA4)
		recInnocent := httptest.NewRecorder()

		if err := f.mw.ServeHTTP(recInnocent, innocentReq, f.next); err != nil {
			t.Fatalf("unexpected error for innocent user: %v", err)
		}
		if recInnocent.Code != http.StatusOK {
			t.Errorf("innocent user on shared IP expected status 200, got %d", recInnocent.Code)
		}
	})

	// Scenario 6: Audit Mode Does Not Auto-Ban on Repeated Attacks
	t.Run("Audit Mode Does Not Auto-Ban", func(t *testing.T) {
		control.StoreSnapshot(control.NewConfigSnapshot(200, control.ModeAudit, nil))
		defer control.StoreSnapshot(control.NewConfigSnapshot(200, control.ModeDefense, nil))

		auditIP := "198.51.100.99"
		auditJA4 := "t13d1516h2_audit_attacker"

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data?q=1%27%20OR%20%271%27=%271", nil)
			req.Header.Set("Authorization", "Bearer token-audit")
			req.Header.Set("X-Real-IP", auditIP)
			req.Header.Set("X-JA4-Fingerprint", auditJA4)
			rec := httptest.NewRecorder()

			_ = f.mw.ServeHTTP(rec, req, f.next)
			if rec.Code != http.StatusOK {
				t.Errorf("audit attack %d expected 200 OK, got %d", i+1, rec.Code)
			}
		}

		ipParsed := net.ParseIP(auditIP)
		isBanned, _ := f.mw.BanManager().IsBanned(ipParsed, auditJA4)
		if isBanned {
			t.Errorf("client must NOT be auto-banned in audit mode")
		}
	})
}
