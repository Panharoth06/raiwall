//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/pkg/bot"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/proxy"
	"github.com/Panharoth06/raiwall/pkg/rate"
)

func TestEndToEndRateLimitAndDDoSDefense(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(200, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
	})

	// 1. Mock protected upstream backend
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

	// 2. Setup Raiwall Middleware with full 3-Tier Rate Limiting and Waiting Room
	powSecret := "e2e-rate-limit-secret-32-bytes"
	mw := &proxy.Middleware{
		Mode:          "defense",
		BotDefense:    "defense",
		PoWSecret:     powSecret,
		PoWDifficulty: 200,
		RateLimitConfig: &proxy.RateLimitSettings{
			Tier1Rate:        10,
			Tier1Period:      caddy.Duration(time.Second),
			Tier1Burst:       5, // Capacity = 6 requests
			Tier2Threshold:   3, // 3 attacks trigger auto-ban
			Tier2Window:      caddy.Duration(time.Second),
			Tier2BanDuration: caddy.Duration(1 * time.Hour),
			Tier3Threshold:   3, // 3 404s trigger auto-ban
			Tier3Window:      caddy.Duration(time.Second),
			Tier3BanDuration: caddy.Duration(1 * time.Hour),
			StorageType:      "memory",
		},
		WaitingRoomConfig: &proxy.WaitingRoomSettings{
			Enabled:               true,
			MaxConcurrentInFlight: 3,
			MaxQueueDepth:         4,
			AdmissionRate:         10,
			AdmissionTokenTTL:     caddy.Duration(15 * time.Minute),
		},
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	next := &e2eNextHandler{handler: backendMux}

	// ------------------------------------------------------------------
	// Scenario 1: Tier 1 Flood - Browser Receives PoW, API Receives 429
	// ------------------------------------------------------------------
	t.Run("Tier 1 Flood: Browser PoW vs API 429", func(t *testing.T) {
		browserIP := "198.51.100.10"
		apiIP := "198.51.100.20"
		ja4 := "t13d1516h2_8daaf6152771_0123456789ab"

		// Flood browser route (/dashboard) with 8 requests (capacity is 6)
		var gotChallenge bool
		for i := 0; i < 8; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
			req.Header.Set("X-Real-IP", browserIP)
			req.Header.Set("X-JA4-Fingerprint", ja4)
			rec := httptest.NewRecorder()

			if err := mw.ServeHTTP(rec, req, next); err != nil {
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

		// Flood API route (/api/data) with 8 requests
		var got429 bool
		for i := 0; i < 8; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
			req.Header.Set("Authorization", "Bearer sk_api_token_123")
			req.Header.Set("X-Real-IP", apiIP)
			req.Header.Set("X-JA4-Fingerprint", ja4)
			rec := httptest.NewRecorder()

			if err := mw.ServeHTTP(rec, req, next); err != nil {
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

	// ------------------------------------------------------------------
	// Scenario 2: Tier 2 Repeated Attack Auto-Ban
	// ------------------------------------------------------------------
	t.Run("Tier 2 Repeated Attacks Trigger Auto-Ban", func(t *testing.T) {
		attackerIP := "198.51.100.66"
		attackerJA4 := "t13d1516h2_attacker_signature"

		// Send repeated attacks (SQL injection) to API route (4 attacks, within Tier 1 burst of 5)
		for i := 0; i < 4; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data?q=1%27%20OR%20%271%27=%271", nil)
			req.Header.Set("Authorization", "Bearer token-attacker")
			req.Header.Set("X-Real-IP", attackerIP)
			req.Header.Set("X-JA4-Fingerprint", attackerJA4)
			rec := httptest.NewRecorder()

			_ = mw.ServeHTTP(rec, req, next)
			if rec.Code != http.StatusForbidden {
				t.Errorf("attack %d expected 403, got %d", i+1, rec.Code)
			}
		}

		// Verify client is now auto-banned in BanManager
		ipParsed := net.ParseIP(attackerIP)
		isBanned, entry := mw.BanManager().IsBanned(ipParsed, attackerJA4)
		if !isBanned || entry == nil {
			t.Fatalf("expected attacker to be auto-banned in BanManager after repeated attacks")
		}

		// Subsequent benign request from banned client is immediately blocked on fast-path
		benignReq := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		benignReq.Header.Set("Authorization", "Bearer token-attacker")
		benignReq.Header.Set("X-Real-IP", attackerIP)
		benignReq.Header.Set("X-JA4-Fingerprint", attackerJA4)
		recBenign := httptest.NewRecorder()

		if err := mw.ServeHTTP(recBenign, benignReq, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if recBenign.Code != http.StatusForbidden {
			t.Errorf("banned client benign request expected 403, got %d", recBenign.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 3: Tier 3 Scanner Trap with Anti-CGNAT Protection
	// ------------------------------------------------------------------
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

		// Scanner probes non-existent backend API endpoints (returns 404 from backend)
		for _, path := range fuzzTargets {
			req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
			req.Header.Set("Authorization", "Bearer scanner-recon")
			req.Header.Set("X-Real-IP", sharedIP)
			req.Header.Set("X-JA4-Fingerprint", scannerJA4)
			rec := httptest.NewRecorder()

			_ = mw.ServeHTTP(rec, req, next)
		}

		// Verify scanner is auto-banned in BanManager
		ipParsed := net.ParseIP(sharedIP)
		isScannerBanned, _ := mw.BanManager().IsBanned(ipParsed, scannerJA4)
		if !isScannerBanned {
			t.Fatalf("expected scanner to be auto-banned after reconnaissance flood")
		}

		// Anti-CGNAT Verification: Innocent browser on the SAME shared IP must NOT be banned!
		isInnocentBanned, _ := mw.BanManager().IsBanned(ipParsed, innocentJA4)
		if isInnocentBanned {
			t.Fatalf("innocent user sharing CGNAT IP must NOT be banned when scanner is banned!")
		}

		// Innocent user can access the API on that shared IP successfully
		innocentReq := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		innocentReq.Header.Set("Authorization", "Bearer jwt-innocent")
		innocentReq.Header.Set("X-Real-IP", sharedIP)
		innocentReq.Header.Set("X-JA4-Fingerprint", innocentJA4)
		recInnocent := httptest.NewRecorder()

		if err := mw.ServeHTTP(recInnocent, innocentReq, next); err != nil {
			t.Fatalf("unexpected error for innocent user: %v", err)
		}
		if recInnocent.Code != http.StatusOK {
			t.Errorf("innocent user on shared IP expected status 200, got %d", recInnocent.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 4: Bounded Virtual Waiting Room & SSE Flow
	// ------------------------------------------------------------------
	t.Run("Waiting Room Queue, SSE Stream, Admission and Load Shedding", func(t *testing.T) {
		wm := mw.WaitingRoom()
		if wm == nil {
			t.Fatal("waiting room not provisioned")
		}
		defer wm.Clear()

		// Fill in-flight capacity (MaxConcurrentInFlight = 3)
		rel1 := wm.AcquireLease()
		defer rel1()
		rel2 := wm.AcquireLease()
		defer rel2()
		rel3 := wm.AcquireLease()
		defer rel3()

		queueIP := "198.51.100.77"
		queueJA4 := "t13d1516h2_waiting_client"

		// 1. Unadmitted browser request hits waiting room page (HTTP 503)
		reqWait := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		reqWait.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqWait.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		reqWait.Header.Set("X-Real-IP", queueIP)
		reqWait.Header.Set("X-JA4-Fingerprint", queueJA4)
		recWait := httptest.NewRecorder()

		_ = mw.ServeHTTP(recWait, reqWait, next)
		if recWait.Code != http.StatusServiceUnavailable {
			t.Errorf("expected waiting room page (status 503), got %d", recWait.Code)
		}
		if !strings.Contains(recWait.Body.String(), "You are in the queue") {
			t.Errorf("expected queue HTML page in body, got: %s", recWait.Body.String())
		}

		// 2. Machine API route receives 503 JSON load shedding immediately
		reqAPI := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		reqAPI.Header.Set("Authorization", "Bearer sk_token")
		reqAPI.Header.Set("X-Real-IP", queueIP)
		reqAPI.Header.Set("X-JA4-Fingerprint", queueJA4)
		recAPI := httptest.NewRecorder()

		_ = mw.ServeHTTP(recAPI, reqAPI, next)
		if recAPI.Code != http.StatusServiceUnavailable {
			t.Errorf("API route in waiting room expected 503 JSON, got %d", recAPI.Code)
		}
		var apiOverload rate.WaitingRoomAPIOverloadedResponse
		if err := json.Unmarshal(recAPI.Body.Bytes(), &apiOverload); err != nil {
			t.Fatalf("failed to parse overloaded JSON: %v", err)
		}
		if apiOverload.Error != "server_overloaded" {
			t.Errorf("expected server_overloaded in JSON, got: %s", apiOverload.Error)
		}

		// 3. Admission token grants direct access even when at capacity
		validToken := wm.GenerateAdmissionToken(net.ParseIP(queueIP), queueJA4, 15*time.Minute)
		reqAdmitted := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		reqAdmitted.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqAdmitted.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		reqAdmitted.Header.Set("X-Real-IP", queueIP)
		reqAdmitted.Header.Set("X-JA4-Fingerprint", queueJA4)
		reqAdmitted.AddCookie(&http.Cookie{Name: rate.WaitingRoomClearanceCookie, Value: validToken})
		recAdmitted := httptest.NewRecorder()

		if err := mw.ServeHTTP(recAdmitted, reqAdmitted, next); err != nil {
			t.Fatalf("unexpected error for admitted client: %v", err)
		}
		if recAdmitted.Code != http.StatusOK {
			t.Errorf("admitted client expected status 200, got %d", recAdmitted.Code)
		}

		// 4. Load Shedding: Enqueue up to max_queue_depth (4)
		ipP := net.ParseIP("198.51.100.88")
		for i := 0; i < 4; i++ {
			_, _, _, _ = wm.Enqueue(ipP, "ja4-shed")
		}
		// Next enqueue exceeds maxQueueDepth -> returns load shed error
		_, _, _, err := wm.Enqueue(ipP, "ja4-shed")
		if err == nil {
			t.Errorf("expected load shedding when exceeding maxQueueDepth")
		}
	})

	// ------------------------------------------------------------------
	// Scenario 5: High Concurrency Race Detector Verification
	// ------------------------------------------------------------------
	t.Run("High Concurrency Requests Pass Race Detector", func(t *testing.T) {
		const numClients = 20
		const requestsPerClient = 10
		var wg sync.WaitGroup

		for c := 0; c < numClients; c++ {
			wg.Add(1)
			go func(clientID int) {
				defer wg.Done()
				clientIP := "198.51.200." + string(rune('1'+(clientID%9)))
				ja4 := "t13d1516h2_concurrent_ja4"

				for r := 0; r < requestsPerClient; r++ {
					req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
					req.Header.Set("Authorization", "Bearer jwt-concurrent")
					req.Header.Set("X-Real-IP", clientIP)
					req.Header.Set("X-JA4-Fingerprint", ja4)
					rec := httptest.NewRecorder()

					_ = mw.ServeHTTP(rec, req, next)
				}
			}(c)
		}

		wg.Wait()
	})

	// ------------------------------------------------------------------
	// Scenario 6: Audit Mode Does Not Auto-Ban on Repeated Attacks
	// ------------------------------------------------------------------
	t.Run("Audit Mode Does Not Auto-Ban", func(t *testing.T) {
		config.StoreSnapshot(config.NewConfigSnapshot(200, config.ModeAudit, nil))
		defer config.StoreSnapshot(config.NewConfigSnapshot(200, config.ModeDefense, nil))

		auditIP := "198.51.100.99"
		auditJA4 := "t13d1516h2_audit_attacker"

		// Send repeated attacks (SQL injection)
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api/data?q=1%27%20OR%20%271%27=%271", nil)
			req.Header.Set("Authorization", "Bearer token-audit")
			req.Header.Set("X-Real-IP", auditIP)
			req.Header.Set("X-JA4-Fingerprint", auditJA4)
			rec := httptest.NewRecorder()

			_ = mw.ServeHTTP(rec, req, next)
			// In audit mode, attacks are logged but not blocked (200 OK from backend)
			if rec.Code != http.StatusOK {
				t.Errorf("audit attack %d expected 200 OK, got %d", i+1, rec.Code)
			}
		}

		// Ensure client is NOT banned in BanManager
		ipParsed := net.ParseIP(auditIP)
		isBanned, _ := mw.BanManager().IsBanned(ipParsed, auditJA4)
		if isBanned {
			t.Errorf("client must NOT be auto-banned in audit mode")
		}
	})

	// ------------------------------------------------------------------
	// Scenario 7: Verified Browser Receives HTTP 429 on Velocity Trip
	// ------------------------------------------------------------------
	t.Run("Verified Browser Receives HTTP 429 on Velocity Trip", func(t *testing.T) {
		verifiedIP := "198.51.100.123"
		verifiedJA4 := "t13d1516h2_verified_client"

		// Generate valid clearance cookie using same powSecret
		clearanceMgr := bot.NewClearanceManager(bot.ClearanceConfig{
			Secret: powSecret,
			TTL:    15 * time.Minute,
		}, nil)
		token := clearanceMgr.GenerateToken(net.ParseIP(verifiedIP), verifiedJA4, time.Now().Add(15*time.Minute))
		clearanceCookie := &http.Cookie{
			Name:  bot.ClearanceCookieName,
			Value: token,
		}

		// Flood browser route (/dashboard) with 8 requests (capacity is 6)
		var got429 bool
		var gotPoW bool
		for i := 0; i < 8; i++ {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
			req.Header.Set("X-Real-IP", verifiedIP)
			req.Header.Set("X-JA4-Fingerprint", verifiedJA4)
			req.AddCookie(clearanceCookie)
			rec := httptest.NewRecorder()

			_ = mw.ServeHTTP(rec, req, next)
			if rec.Code == http.StatusTooManyRequests {
				got429 = true
				if rec.Header().Get("Retry-After") == "" {
					t.Errorf("verified browser 429 missing Retry-After header")
				}
				break
			} else if rec.Code == bot.HTTPStatusChallenge {
				gotPoW = true
			}
		}

		if gotPoW {
			t.Errorf("verified browser should NOT receive another HTTP 468 PoW challenge")
		}
		if !got429 {
			t.Errorf("verified browser flood should have triggered HTTP 429 Too Many Requests")
		}
	})

	// ------------------------------------------------------------------
	// Scenario 8: Virtual Waiting Room Position Preservation via Cookie
	// ------------------------------------------------------------------
	t.Run("Virtual Waiting Room Position Preservation via Cookie", func(t *testing.T) {
		mwWait := &proxy.Middleware{
			Mode:          "defense",
			BotDefense:    "defense",
			PoWSecret:     powSecret,
			PoWDifficulty: 200,
			WaitingRoomConfig: &proxy.WaitingRoomSettings{
				Enabled:               true,
				MaxConcurrentInFlight: 1,
				MaxQueueDepth:         10,
				AdmissionRate:         10,
				AdmissionTokenTTL:     caddy.Duration(15 * time.Minute),
			},
		}
		cCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()
		if err := mwWait.Provision(cCtx); err != nil {
			t.Fatalf("failed to provision middleware: %v", err)
		}
		defer func() {
			_ = mwWait.Cleanup()
		}()

		wm := mwWait.WaitingRoom()
		// Hold the single in-flight lease
		rel := wm.AcquireLease()
		defer rel()

		cookieIP := "198.51.100.155"
		cookieJA4 := "t13d1516h2_queue_cookie_test"

		// 1. Initial request to waiting room
		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		req1.Header.Set("Accept", "text/html,application/xhtml+xml")
		req1.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		req1.Header.Set("X-Real-IP", cookieIP)
		req1.Header.Set("X-JA4-Fingerprint", cookieJA4)
		rec1 := httptest.NewRecorder()

		_ = mwWait.ServeHTTP(rec1, req1, next)
		if rec1.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected status 503, got %d", rec1.Code)
		}

		// Extract queue cookie
		var queueCookie *http.Cookie
		for _, c := range rec1.Result().Cookies() {
			if c.Name == rate.WaitingRoomQueueCookie {
				queueCookie = c
				break
			}
		}
		if queueCookie == nil || queueCookie.Value == "" {
			t.Fatalf("expected %s cookie in response", rate.WaitingRoomQueueCookie)
		}

		// 2. Client refreshes with queue cookie
		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		req2.Header.Set("Accept", "text/html,application/xhtml+xml")
		req2.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		req2.Header.Set("X-Real-IP", cookieIP)
		req2.Header.Set("X-JA4-Fingerprint", cookieJA4)
		req2.AddCookie(queueCookie)
		rec2 := httptest.NewRecorder()

		_ = mwWait.ServeHTTP(rec2, req2, next)
		if rec2.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected status 503 on refresh, got %d", rec2.Code)
		}

		// Ensure queue depth is still 1 (not duplicated)
		if depth := wm.QueueDepth(); depth != 1 {
			t.Errorf("expected queue depth 1 on refresh with cookie, got %d", depth)
		}
	})
}
