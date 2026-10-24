//go:build integration

package e2e

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/geoip"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

type accessControlFixture struct {
	mw                  *caddy.Middleware
	next                *e2eNextHandler
	sessionMgr          *auth.SessionManager
	lastReceivedHeaders *sync.Map
}

func setupAccessControlFixture(t *testing.T) *accessControlFixture {
	t.Helper()

	control.StoreSnapshot(control.NewConfigSnapshot(300, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	backendMux := http.NewServeMux()
	var lastReceivedHeaders sync.Map

	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lastReceivedHeaders.Store(r.URL.Path, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","message":"backend reached"}`))
	})

	exEngine, err := acl.NewExceptionEngine(&acl.ExceptionRule{
		ID:         "EX_SEARCH_Q",
		Host:       "example.com",
		PathPrefix: "/search",
		Method:     "GET",
		Location:   "query",
		ParamName:  "q",
		RuleID:     "SEMANTIC_SQLI",
	})
	if err != nil {
		t.Fatalf("failed to create exception engine: %v", err)
	}

	bartTable := acl.NewBARTTable()
	_ = bartTable.InsertCIDR("203.0.113.50/32", "emerging_threats", "Known scanner IP")
	_ = bartTable.InsertCIDR("198.51.100.0/24", "tor_exit_nodes", "Tor exit relay")

	geoReader := geoip.NewNoopGeoIPReader()
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.10"), acl.GeoData{Country: "KP", ASN: 1234})
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.20"), acl.GeoData{Country: "US", ASN: 15169})
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.30"), acl.GeoData{Country: "DE", ASN: 3320})

	aclRules := []*acl.ACLRule{
		{
			Name:       "geo_fence_high_risk",
			Expression: `geo.Country == "KP" || geo.Country == "IR"`,
			Action:     acl.ActionBlock,
			Priority:   10,
			StatusCode: 451,
		},
		{
			Name:       "complex_admin_policy",
			Expression: `has_prefix(path, "/api/admin") && (headers["x-admin-key"] != "supersecret" || geo.Country != "US")`,
			Action:     acl.ActionBlock,
			Priority:   20,
			StatusCode: 403,
		},
		{
			Name:        "redirect_legacy_portal",
			Expression:  `has_prefix(path, "/legacy")`,
			Action:      acl.ActionRedirect,
			Priority:    30,
			StatusCode:  301,
			RedirectURL: "/portal",
		},
	}
	aclEngine, err := acl.NewACLEngine(bartTable, geoReader, aclRules...)
	if err != nil {
		t.Fatalf("failed to create ACL engine: %v", err)
	}

	sessionSecret := "testing-e2e-session-secret-32-bytes!"
	simpleAuth := auth.NewSimpleAuth(auth.SimpleUser{
		Username:     "alice",
		PasswordHash: "secretpass123",
		Email:        "alice@corp.internal",
		Name:         "Alice Smith",
		Roles:        []string{"admin", "developer"},
	})
	authGate := auth.NewAppAuthGate(sessionSecret, nil, nil,
		auth.WithSimpleAuth(simpleAuth),
		auth.WithBypassPaths("/public/*", "/search", "/healthz", "/legacy*"),
	)
	sessionMgr := authGate.SessionManager()

	semEngine := waf.NewSemanticEngine(waf.WithExceptionEngine(exEngine))

	mw := &caddy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}
	mw.SetExceptionEngine(exEngine)
	mw.SetBARTTable(bartTable)
	mw.SetGeoIPReader(geoReader)
	mw.SetACLEngine(aclEngine)
	mw.SetGlobalAuthGate(authGate)
	mw.SetEngine(semEngine)

	return &accessControlFixture{
		mw:                  mw,
		next:                &e2eNextHandler{handler: backendMux},
		sessionMgr:          sessionMgr,
		lastReceivedHeaders: &lastReceivedHeaders,
	}
}

func TestEndToEndAccessControl_RulesAndFeeds(t *testing.T) {
	f := setupAccessControlFixture(t)

	// Scenario 1: Parameter Whitelist Bypass vs Adjacent Attack Block
	t.Run("Parameter Exception Gate: Whitelisted vs Adjacent Attack", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+OR+%271%27%3D%271", nil)
		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected whitelisted parameter to pass (200), got %d", rec.Code)
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/search?filter=%27+OR+%271%27%3D%271", nil)
		rec2 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec2, req2, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusForbidden {
			t.Errorf("expected adjacent malicious parameter to be blocked (403), got %d", rec2.Code)
		}
	})

	// Scenario 2: Threat Feed IP Matching in BART Table
	t.Run("BART Threat Feed Fast-Path Ban", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/status", nil)
		req.RemoteAddr = "203.0.113.50:4321" // Matches emerging_threats
		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected threat feed IP to be blocked (403), got %d", rec.Code)
		}
		if rec.Header().Get("X-Raiwall-Event-ID") == "" {
			t.Error("expected X-Raiwall-Event-ID header on blocked threat feed request")
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/public/status", nil)
		req2.RemoteAddr = "192.0.2.100:4321" // Clean IP
		rec2 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec2, req2, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusOK {
			t.Errorf("expected clean IP to pass (200), got %d", rec2.Code)
		}
	})

	// Scenario 3: GeoIP Country Fencing
	t.Run("GeoIP Country Fencing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/content", nil)
		req.RemoteAddr = "192.0.2.10:1234" // Mapped to Country: "KP"
		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != 451 {
			t.Errorf("expected GeoIP blocked country to receive 451, got %d", rec.Code)
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/public/content", nil)
		req2.RemoteAddr = "192.0.2.20:1234" // Mapped to Country: "US"
		rec2 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec2, req2, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusOK {
			t.Errorf("expected allowed country to pass (200), got %d", rec2.Code)
		}
	})

	// Scenario 4: Bytecode expr Complex Multi-Condition Rules
	t.Run("Multi-Condition Bytecode Evaluation", func(t *testing.T) {
		cookie, _ := f.sessionMgr.CreateSessionCookie(&auth.UserIdentity{Subject: "alice"})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req.RemoteAddr = "192.0.2.20:5678" // US
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec, req, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected missing admin key to be blocked (403), got %d", rec.Code)
		}

		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req2.RemoteAddr = "192.0.2.30:5678" // DE
		req2.Header.Set("X-Admin-Key", "supersecret")
		req2.AddCookie(cookie)
		rec2 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec2, req2, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusForbidden {
			t.Errorf("expected admin request from non-US country to be blocked (403), got %d", rec2.Code)
		}

		req3 := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req3.RemoteAddr = "192.0.2.20:5678" // US
		req3.Header.Set("X-Admin-Key", "supersecret")
		req3.AddCookie(cookie)
		rec3 := httptest.NewRecorder()
		if err := f.mw.ServeHTTP(rec3, req3, f.next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec3.Code != http.StatusOK {
			t.Errorf("expected valid multi-condition request to pass (200), got %d", rec3.Code)
		}
	})
}
