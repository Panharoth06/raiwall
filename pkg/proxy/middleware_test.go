package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/auth"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
)

type mockNextHandler struct {
	invoked      bool
	receivedHead http.Header
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.invoked = true
	m.receivedHead = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("backend ok"))
	return nil
}

func TestMiddleware_AuthGateway_ServeHTTP(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(100, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
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
			SessionTTL:    caddy.Duration(1 * time.Hour),
			BypassPaths:   []string{"/public/*", "/healthz"},
		},
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
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

func TestMiddleware_ACLEngine_ServeHTTP(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(100, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
	})

	bartTable := acl.NewBARTTable()
	_ = bartTable.InsertCIDR("203.0.113.100", "tor", "Tor exit node")

	rules := []*acl.ACLRule{
		{
			Name:       "block_admin_external",
			Expression: "has_prefix(path, '/admin') && in_cidr(ip, '10.0.0.0/8') == false",
			Action:     acl.ActionBlock,
			Priority:   10,
			StatusCode: 403,
		},
		{
			Name:        "redirect_old_docs",
			Expression:  "has_prefix(path, '/docs/v1')",
			Action:      acl.ActionRedirect,
			Priority:    20,
			StatusCode:  301,
			RedirectURL: "/docs/v2",
		},
		{
			Name:       "allow_trusted_partner",
			Expression: "headers['x-partner-key'] == 'trusted-token'",
			Action:     acl.ActionAllow,
			Priority:   30,
		},
	}

	aclEng, err := acl.NewACLEngine(bartTable, nil, rules...)
	if err != nil {
		t.Fatalf("failed to create ACLEngine: %v", err)
	}

	mw := &Middleware{
		Mode: "defense",
	}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mw.SetACLEngine(aclEng)
	mw.SetBARTTable(bartTable)

	t.Run("ACL rule blocks external admin access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/admin/settings", nil)
		req.RemoteAddr = "198.51.100.25:12345"
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not have been invoked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
		if rec.Header().Get("X-Raiwall-Event-ID") == "" {
			t.Error("expected X-Raiwall-Event-ID header")
		}
	})

	t.Run("ACL rule redirects legacy docs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/docs/v1/intro", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not have been invoked")
		}
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rec.Code)
		}
		if rec.Header().Get("Location") != "/docs/v2" {
			t.Errorf("expected Location /docs/v2, got %q", rec.Header().Get("Location"))
		}
	})

	t.Run("Direct BART threat feed match blocks IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/index", nil)
		req.RemoteAddr = "203.0.113.100:54321"
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if next.invoked {
			t.Error("upstream should not have been invoked for threat feed IP")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})
}

func TestMiddleware_ExceptionEngine_ServeHTTP(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(100, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
	})

	// Create ExceptionEngine whitelisting parameter 'q' on path '/search'
	exEng, err := acl.NewExceptionEngine(&acl.ExceptionRule{
		ID:        "EX_SEARCH_QUERY",
		Host:      "example.com",
		PathPrefix: "/search",
		Method:    "GET",
		Location:  "query",
		ParamName: "q",
		RuleID:    "*",
	})
	if err != nil {
		t.Fatalf("failed to create ExceptionEngine: %v", err)
	}

	semEng := engine.NewSemanticEngine(engine.WithExceptionEngine(exEng))

	mw := &Middleware{
		Mode: "defense",
	}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mw.engine = semEng
	mw.SetExceptionEngine(exEng)

	t.Run("Excepted parameter with SQLi bypasses WAF", func(t *testing.T) {
		// ' UNION SELECT 1,2,3-- in parameter 'q' is excepted
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+UNION+SELECT+1%2C2%2C3--", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if !next.invoked {
			t.Error("expected request with excepted parameter to pass to upstream")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Non-excepted parameter with SQLi is blocked", func(t *testing.T) {
		// ' UNION SELECT 1,2,3-- in parameter 'category' is NOT excepted
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?category=%27+UNION+SELECT+1%2C2%2C3--", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if next.invoked {
			t.Error("expected non-excepted attack parameter to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})
}
