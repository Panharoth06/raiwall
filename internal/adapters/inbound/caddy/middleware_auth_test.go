package caddy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestMiddleware_AuthGateway_ServeHTTP(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	sessionSecret := "testing-session-secret-key-32-chars!!"
	sessionMgr := auth.NewSessionManager(sessionSecret, auth.WithCookieTTL(1*time.Hour))
	simpleAuth := auth.NewSimpleAuth(auth.SimpleUser{
		Username:     "alice",
		PasswordHash: "secretpass",
		Email:        "alice@example.com",
		Roles:        []string{"admin", "editor"},
	})

	mw := &Middleware{
		Mode: "defense",
		AuthConfig: &AuthSettings{
			Provider:      "simple",
			SessionSecret: sessionSecret,
			SessionTTL:    caddyv2.Duration(1 * time.Hour),
			BypassPaths:   []string{"/public/*", "/healthz"},
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	gwCfg := auth.GatewayConfig{
		SimpleAuth:  simpleAuth,
		SessionMgr:  sessionMgr,
		BypassPaths: []string{"/public/*", "/healthz"},
	}
	mw.SetAuthGateway(auth.NewAuthGateway(gwCfg))

	t.Run("Browser unauthenticated redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/dashboard", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not have been invoked")
		}
		if rec.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rec.Code)
		}
		location := rec.Header().Get("Location")
		if !strings.HasPrefix(location, auth.AuthLoginPath) {
			t.Errorf("expected redirect to login path, got %q", location)
		}
	})

	t.Run("API unauthenticated returns 401 JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/data", nil)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not have been invoked")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid json response: %v", err)
		}
		if resp["error"] != "unauthorized" {
			t.Errorf("unexpected json response: %v", resp)
		}
	})

	t.Run("Bypass path passes through and strips untrusted headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/about", nil)
		req.Header.Set("X-Auth-Subject", "hacker")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if !next.invoked {
			t.Fatal("expected upstream to be invoked")
		}
		if next.receivedHead.Get(auth.HeaderAuthSubject) != "" {
			t.Errorf("untrusted X-Auth-Subject was not stripped: %q", next.receivedHead.Get(auth.HeaderAuthSubject))
		}
	})

	t.Run("Authenticated session injects identity headers upstream", func(t *testing.T) {
		cookie, err := sessionMgr.CreateSessionCookie(&auth.UserIdentity{
			Subject: "alice",
			Email:   "alice@example.com",
			Name:    "Alice Admin",
			Roles:   []string{"admin", "editor"},
		})
		if err != nil {
			t.Fatalf("failed to create session cookie: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/dashboard", nil)
		req.AddCookie(cookie)
		req.Header.Set("X-Auth-Subject", "spoofed")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err = mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if !next.invoked {
			t.Fatal("expected upstream to be invoked")
		}
		if next.receivedHead.Get(auth.HeaderAuthSubject) != "alice" {
			t.Errorf("expected X-Auth-Subject 'alice', got %q", next.receivedHead.Get(auth.HeaderAuthSubject))
		}
		if next.receivedHead.Get(auth.HeaderAuthEmail) != "alice@example.com" {
			t.Errorf("expected X-Auth-Email 'alice@example.com', got %q", next.receivedHead.Get(auth.HeaderAuthEmail))
		}
		if next.receivedHead.Get(auth.HeaderAuthRoles) != "admin,editor" {
			t.Errorf("expected X-Auth-Roles 'admin,editor', got %q", next.receivedHead.Get(auth.HeaderAuthRoles))
		}
	})

	t.Run("Direct auth endpoint renders login page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+auth.AuthLoginPath, nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not be invoked for login endpoint")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Raiwall Zero-Trust Security Gateway") {
			t.Errorf("expected login page content, got %s", rec.Body.String())
		}
	})
}
