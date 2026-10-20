//go:build integration

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestEndToEndAccessControl_AuthAndSessions(t *testing.T) {
	f := setupAccessControlFixture(t)

	// Scenario 5: Pre-Application Auth Gateway Redirection & 401
	t.Run("Pre-App Auth Redirection & API 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/private/dashboard", nil)
		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("expected browser redirect (302), got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/.raiwall/auth/login") {
			t.Errorf("expected redirect to /.raiwall/auth/login, got %q", loc)
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/api/private/metrics", nil)
		req2.Header.Set("Accept", "application/json")
		rec2 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec2, req2, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusUnauthorized {
			t.Errorf("expected API unauthorized (401), got %d", rec2.Code)
		}
		var errResp map[string]string
		if err := json.Unmarshal(rec2.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("invalid json 401 response: %v", err)
		}
		if errResp["error"] != "unauthorized" {
			t.Errorf("expected error 'unauthorized', got %q", errResp["error"])
		}
	})

	// Scenario 6: Authenticated Session with Upstream Identity Injection
	t.Run("Authenticated Session and Upstream Identity Header Injection", func(t *testing.T) {
		cookie, err := f.sessionMgr.CreateSessionCookie(&auth.UserIdentity{
			Subject: "alice",
			Email:   "alice@corp.internal",
			Name:    "Alice Smith",
			Roles:   []string{"admin", "developer"},
		})
		if err != nil {
			t.Fatalf("failed to create session cookie: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/private/profile", nil)
		req.AddCookie(cookie)
		req.Header.Set("X-Auth-Subject", "evil-spoofed-subject")
		req.Header.Set("X-Auth-Roles", "super-root")

		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected authenticated request to pass (200), got %d", rec.Code)
		}

		val, ok := f.lastReceivedHeaders.Load("/private/profile")
		if !ok {
			t.Fatal("backend did not record headers for /private/profile")
		}
		upHeaders := val.(http.Header)

		if upHeaders.Get(auth.HeaderAuthSubject) != "alice" {
			t.Errorf("expected upstream X-Auth-Subject 'alice', got %q", upHeaders.Get(auth.HeaderAuthSubject))
		}
		if upHeaders.Get(auth.HeaderAuthEmail) != "alice@corp.internal" {
			t.Errorf("expected upstream X-Auth-Email 'alice@corp.internal', got %q", upHeaders.Get(auth.HeaderAuthEmail))
		}
		if upHeaders.Get(auth.HeaderAuthRoles) != "admin,developer" {
			t.Errorf("expected upstream X-Auth-Roles 'admin,developer', got %q", upHeaders.Get(auth.HeaderAuthRoles))
		}
	})

	// Scenario 7: Bearer Token Authentication & Upstream Injection
	t.Run("Bearer Token Authentication and Upstream Injection", func(t *testing.T) {
		token, err := f.sessionMgr.CreateSessionToken(&auth.UserIdentity{
			Subject: "bob_api",
			Email:   "bob@api.corp",
			Roles:   []string{"service_account"},
		})
		if err != nil {
			t.Fatalf("failed to create session token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected Bearer authenticated request to pass (200), got %d", rec.Code)
		}

		val, ok := f.lastReceivedHeaders.Load("/api/v1/data")
		if !ok {
			t.Fatal("backend did not record headers for /api/v1/data")
		}
		upHeaders := val.(http.Header)
		if upHeaders.Get(auth.HeaderAuthSubject) != "bob_api" {
			t.Errorf("expected upstream X-Auth-Subject 'bob_api', got %q", upHeaders.Get(auth.HeaderAuthSubject))
		}
		if upHeaders.Get(auth.HeaderAuthRoles) != "service_account" {
			t.Errorf("expected upstream X-Auth-Roles 'service_account', got %q", upHeaders.Get(auth.HeaderAuthRoles))
		}
	})

	// Scenario 8: Audit Mode in Access Control and Threat Feeds
	t.Run("Audit Mode Does Not Block Feeds or Rules", func(t *testing.T) {
		control.StoreSnapshot(control.NewConfigSnapshot(301, control.ModeAudit, nil))
		defer control.StoreSnapshot(control.NewConfigSnapshot(300, control.ModeDefense, nil))

		reqKP := httptest.NewRequest(http.MethodGet, "http://example.com/public/audit-geo", nil)
		reqKP.RemoteAddr = "192.0.2.10:1234"
		recKP := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(recKP, reqKP, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if recKP.Code != http.StatusOK {
			t.Errorf("expected KP request in audit mode to pass (200), got %d", recKP.Code)
		}

		reqFeed := httptest.NewRequest(http.MethodGet, "http://example.com/public/audit-feed", nil)
		reqFeed.RemoteAddr = "203.0.113.50:4321"
		recFeed := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(recFeed, reqFeed, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if recFeed.Code != http.StatusOK {
			t.Errorf("expected threat feed IP in audit mode to pass (200), got %d", recFeed.Code)
		}
	})

	// Scenario 9: Concurrent High-Load Verification (-race safety)
	t.Run("Concurrent Access Control Under Load", func(t *testing.T) {
		const concurrency = 20
		const requestsPerGoroutine = 50

		cookie, err := f.sessionMgr.CreateSessionCookie(&auth.UserIdentity{
			Subject: "concurrency_user",
			Email:   "concurrent@corp.internal",
			Roles:   []string{"admin"},
		})
		if err != nil {
			t.Fatalf("failed to create session cookie: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(concurrency)

		for i := 0; i < concurrency; i++ {
			go func(workerID int) {
				defer wg.Done()
				for j := 0; j < requestsPerGoroutine; j++ {
					var req *http.Request
					if j%4 == 0 {
						req = httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+OR+%271%27%3D%271", nil)
					} else if j%4 == 1 {
						req = httptest.NewRequest(http.MethodGet, "http://example.com/public/feed", nil)
						req.RemoteAddr = "203.0.113.50:1111"
					} else if j%4 == 2 {
						req = httptest.NewRequest(http.MethodGet, "http://example.com/public/geo", nil)
						req.RemoteAddr = "192.0.2.10:2222"
					} else {
						req = httptest.NewRequest(http.MethodGet, "http://example.com/private/data", nil)
						req.AddCookie(cookie)
					}

					rec := httptest.NewRecorder()
					_ = f.mw.ServeHTTP(rec, req, f.next)
				}
			}(i)
		}

		wg.Wait()
	})
}
