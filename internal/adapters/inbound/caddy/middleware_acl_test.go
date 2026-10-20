package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestMiddleware_ACLEngine_ServeHTTP(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
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
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
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

	t.Run("Audit mode does not block ACL block rule or threat feed", func(t *testing.T) {
		control.StoreSnapshot(control.NewConfigSnapshot(200, control.ModeAudit, nil))
		defer control.StoreSnapshot(control.NewConfigSnapshot(200, control.ModeDefense, nil))

		req := httptest.NewRequest(http.MethodGet, "http://example.com/admin/settings", nil)
		req.RemoteAddr = "198.51.100.25:12345"
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if !next.invoked {
			t.Error("expected upstream to be invoked in audit mode for ACL block rule")
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/index", nil)
		req2.RemoteAddr = "203.0.113.100:54321"
		rec2 := httptest.NewRecorder()
		next2 := &mockNextHandler{}

		err = mw.ServeHTTP(rec2, req2, next2)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if !next2.invoked {
			t.Error("expected upstream to be invoked in audit mode for threat feed match")
		}
	})
}

func TestMiddleware_AuditMode_ACLAndThreatFeeds(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeAudit, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	bartTable := acl.NewBARTTable()
	_ = bartTable.InsertCIDR("203.0.113.10/32", "threat_feed", "attacker IP")

	rule := &acl.ACLRule{
		Name:       "block_admin",
		Expression: `has_prefix(path, "/admin")`,
		Action:     acl.ActionBlock,
		StatusCode: http.StatusForbidden,
	}
	aclEng, err := acl.NewACLEngine(bartTable, nil, rule)
	if err != nil {
		t.Fatalf("failed to create ACLEngine: %v", err)
	}

	mw := &Middleware{
		Mode: "audit",
	}
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mw.SetBARTTable(bartTable)
	mw.SetACLEngine(aclEng)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/admin/settings", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	if err := mw.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if !next.invoked {
		t.Errorf("expected ACL block rule in audit mode to pass to upstream, but was blocked")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/public/data", nil)
	req2.RemoteAddr = "203.0.113.10:9876"
	rec2 := httptest.NewRecorder()
	next2 := &mockNextHandler{}

	if err := mw.ServeHTTP(rec2, req2, next2); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if !next2.invoked {
		t.Errorf("expected threat feed IP in audit mode to pass to upstream, but was blocked")
	}
}
