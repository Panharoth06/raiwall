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
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

func TestEndToEndRateLimit_WaitingRoomAndConcurrency(t *testing.T) {
	f := setupRateLimitFixture(t)

	// Scenario 4: Bounded Virtual Waiting Room & SSE Flow
	t.Run("Waiting Room Queue, SSE Stream, Admission and Load Shedding", func(t *testing.T) {
		wm := f.mw.WaitingRoom()
		if wm == nil {
			t.Fatal("waiting room not provisioned")
		}
		defer wm.Clear()

		rel1 := wm.AcquireLease()
		defer rel1()
		rel2 := wm.AcquireLease()
		defer rel2()
		rel3 := wm.AcquireLease()
		defer rel3()

		queueIP := "198.51.100.77"
		queueJA4 := "t13d1516h2_waiting_client"

		// 1. Unadmitted browser request hits waiting room page (HTTP 465)
		reqWait := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		reqWait.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqWait.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		reqWait.Header.Set("X-Real-IP", queueIP)
		reqWait.Header.Set("X-JA4-Fingerprint", queueJA4)
		recWait := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recWait, reqWait, f.next)
		if recWait.Code != rate.StatusWaitingRoom {
			t.Errorf("expected waiting room page (status %d), got %d", rate.StatusWaitingRoom, recWait.Code)
		}
		if !strings.Contains(recWait.Body.String(), "You are in the queue") {
			t.Errorf("expected queue HTML page in body, got: %s", recWait.Body.String())
		}

		// 2. Machine API route receives 465 JSON load shedding immediately
		reqAPI := httptest.NewRequest(http.MethodGet, "https://example.com/api/data", nil)
		reqAPI.Header.Set("Authorization", "Bearer sk_token")
		reqAPI.Header.Set("X-Real-IP", queueIP)
		reqAPI.Header.Set("X-JA4-Fingerprint", queueJA4)
		recAPI := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recAPI, reqAPI, f.next)
		if recAPI.Code != rate.StatusWaitingRoom {
			t.Errorf("API route in waiting room expected %d JSON, got %d", rate.StatusWaitingRoom, recAPI.Code)
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

		if err := f.mw.ServeHTTP(recAdmitted, reqAdmitted, f.next); err != nil {
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
		_, _, _, err := wm.Enqueue(ipP, "ja4-shed")
		if err == nil {
			t.Errorf("expected load shedding when exceeding maxQueueDepth")
		}
	})

	// Scenario 5: High Concurrency Race Detector Verification
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

					_ = f.mw.ServeHTTP(rec, req, f.next)
				}
			}(c)
		}

		wg.Wait()
	})

	// Scenario 7: Verified Browser Receives HTTP 429 on Velocity Trip
	t.Run("Verified Browser Receives HTTP 429 on Velocity Trip", func(t *testing.T) {
		verifiedIP := "198.51.100.123"
		verifiedJA4 := "t13d1516h2_verified_client"

		clearanceMgr := bot.NewClearanceManager(bot.ClearanceConfig{
			Secret: f.powSecret,
			TTL:    15 * time.Minute,
		}, nil)
		token := clearanceMgr.GenerateToken(net.ParseIP(verifiedIP), verifiedJA4, time.Now().Add(15*time.Minute))
		clearanceCookie := &http.Cookie{
			Name:  bot.ClearanceCookieName,
			Value: token,
		}

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

			_ = f.mw.ServeHTTP(rec, req, f.next)
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

	// Scenario 8: Virtual Waiting Room Position Preservation via Cookie
	t.Run("Virtual Waiting Room Position Preservation via Cookie", func(t *testing.T) {
		mwWait := &caddy.Middleware{
			Mode:          "defense",
			BotDefense:    "defense",
			PoWSecret:     f.powSecret,
			PoWDifficulty: 200,
			WaitingRoomConfig: &caddy.WaitingRoomSettings{
				Enabled:               true,
				MaxConcurrentInFlight: 1,
				MaxQueueDepth:         10,
				AdmissionRate:         10,
				AdmissionTokenTTL:     caddyv2.Duration(15 * time.Minute),
			},
		}
		cCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
		defer cancel()
		if err := mwWait.Provision(cCtx); err != nil {
			t.Fatalf("failed to provision middleware: %v", err)
		}
		defer func() {
			_ = mwWait.Cleanup()
		}()

		wm := mwWait.WaitingRoom()
		rel := wm.AcquireLease()
		defer rel()

		cookieIP := "198.51.100.155"
		cookieJA4 := "t13d1516h2_queue_cookie_test"

		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		req1.Header.Set("Accept", "text/html,application/xhtml+xml")
		req1.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		req1.Header.Set("X-Real-IP", cookieIP)
		req1.Header.Set("X-JA4-Fingerprint", cookieJA4)
		rec1 := httptest.NewRecorder()

		_ = mwWait.ServeHTTP(rec1, req1, f.next)
		if rec1.Code != rate.StatusWaitingRoom {
			t.Fatalf("expected status %d, got %d", rate.StatusWaitingRoom, rec1.Code)
		}

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

		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		req2.Header.Set("Accept", "text/html,application/xhtml+xml")
		req2.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
		req2.Header.Set("X-Real-IP", cookieIP)
		req2.Header.Set("X-JA4-Fingerprint", cookieJA4)
		req2.AddCookie(queueCookie)
		rec2 := httptest.NewRecorder()

		_ = mwWait.ServeHTTP(rec2, req2, f.next)
		if rec2.Code != rate.StatusWaitingRoom {
			t.Fatalf("expected status %d on refresh, got %d", rate.StatusWaitingRoom, rec2.Code)
		}

		if depth := wm.QueueDepth(); depth != 1 {
			t.Errorf("expected queue depth 1 on refresh with cookie, got %d", depth)
		}
	})

	t.Run("Path-Level Targeting: Only configured path prefixes enter waiting room", func(t *testing.T) {
		wm := f.mw.WaitingRoom()
		if wm == nil {
			t.Fatal("waiting room not provisioned")
		}
		defer wm.Clear()
		defer wm.SetTargetPaths(nil)

		// Set target paths: only queue /tickets/* and /checkout
		wm.SetTargetPaths([]string{"/tickets/*", "/checkout"})

		// Saturate waiting room with active leases
		rel1 := wm.AcquireLease()
		defer rel1()
		rel2 := wm.AcquireLease()
		defer rel2()
		rel3 := wm.AcquireLease()
		defer rel3()

		clientIP := "198.51.100.99"
		clientJA4 := "t13d1516h2_path_target_test"

		// 1. Request to unconfigured path (/dashboard) bypasses waiting room directly to upstream
		reqNonTarget := httptest.NewRequest(http.MethodGet, "https://example.com/dashboard", nil)
		reqNonTarget.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqNonTarget.Header.Set("User-Agent", "Mozilla/5.0")
		reqNonTarget.Header.Set("X-Real-IP", clientIP)
		reqNonTarget.Header.Set("X-JA4-Fingerprint", clientJA4)
		recNonTarget := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recNonTarget, reqNonTarget, f.next)
		if recNonTarget.Code != http.StatusOK {
			t.Errorf("expected non-targeted path /dashboard to return 200, got %d", recNonTarget.Code)
		}

		// 2. Request to targeted path (/tickets/buy) enters waiting room and gets HTTP 465
		reqTarget := httptest.NewRequest(http.MethodGet, "https://example.com/tickets/buy", nil)
		reqTarget.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqTarget.Header.Set("User-Agent", "Mozilla/5.0")
		reqTarget.Header.Set("X-Real-IP", clientIP)
		reqTarget.Header.Set("X-JA4-Fingerprint", clientJA4)
		recTarget := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recTarget, reqTarget, f.next)
		if recTarget.Code != rate.StatusWaitingRoom {
			t.Errorf("expected targeted path /tickets/buy to return %d, got %d", rate.StatusWaitingRoom, recTarget.Code)
		}

		// 3. Request to /tickets_cancel must NOT match /tickets/* and bypass waiting room
		reqBoundary := httptest.NewRequest(http.MethodGet, "https://example.com/tickets_cancel", nil)
		reqBoundary.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqBoundary.Header.Set("User-Agent", "Mozilla/5.0")
		reqBoundary.Header.Set("X-Real-IP", clientIP)
		reqBoundary.Header.Set("X-JA4-Fingerprint", clientJA4)
		recBoundary := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recBoundary, reqBoundary, f.next)
		if recBoundary.Code != http.StatusOK {
			t.Errorf("expected boundary path /tickets_cancel to return 200, got %d", recBoundary.Code)
		}

		// 4. Extract queue cookie from recTarget, admit entry, and verify next request passes with clearance
		cookies := recTarget.Result().Cookies()
		var qCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == rate.WaitingRoomQueueCookie {
				qCookie = c
				break
			}
		}
		if qCookie == nil {
			t.Fatal("expected queue cookie on HTTP 465 response")
		}

		// Admit the queued entry
		wm.AdmitEntry(qCookie.Value)

		// Next request with queue cookie must be granted admission clearance and return 200 OK
		reqAdmitted := httptest.NewRequest(http.MethodGet, "https://example.com/tickets/buy", nil)
		reqAdmitted.Header.Set("Accept", "text/html,application/xhtml+xml")
		reqAdmitted.Header.Set("User-Agent", "Mozilla/5.0")
		reqAdmitted.Header.Set("X-Real-IP", clientIP)
		reqAdmitted.Header.Set("X-JA4-Fingerprint", clientJA4)
		reqAdmitted.AddCookie(qCookie)
		recAdmitted := httptest.NewRecorder()

		_ = f.mw.ServeHTTP(recAdmitted, reqAdmitted, f.next)
		if recAdmitted.Code != http.StatusOK {
			t.Errorf("expected admitted client to pass through with 200, got %d", recAdmitted.Code)
		}

		// Verify clearance cookie was set
		foundClearance := false
		for _, c := range recAdmitted.Result().Cookies() {
			if c.Name == rate.WaitingRoomClearanceCookie {
				foundClearance = true
				break
			}
		}
		if !foundClearance {
			t.Errorf("expected clearance cookie to be set for admitted client")
		}
	})
}
