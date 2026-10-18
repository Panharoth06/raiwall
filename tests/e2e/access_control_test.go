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

	"github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/auth"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/Panharoth06/raiwall/pkg/proxy"
)

func TestEndToEndAccessControlAndZeroTrustGateway(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(300, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
	})

	// 1. Mock upstream backend recording received requests and headers
	backendMux := http.NewServeMux()
	var lastReceivedHeaders sync.Map // path -> http.Header

	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lastReceivedHeaders.Store(r.URL.Path, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","message":"backend reached"}`))
	})

	// 2. Setup components for Domain 5
	// A. Exception Engine: whitelist 'q' on /search for SEMANTIC_SQLI
	exEngine, err := acl.NewExceptionEngine(&acl.ExceptionRule{
		ID:        "EX_SEARCH_Q",
		Host:      "example.com",
		PathPrefix: "/search",
		Method:    "GET",
		Location:  "query",
		ParamName: "q",
		RuleID:    "SEMANTIC_SQLI",
	})
	if err != nil {
		t.Fatalf("failed to create exception engine: %v", err)
	}

	// B. BART Threat Feed table
	bartTable := acl.NewBARTTable()
	_ = bartTable.InsertCIDR("203.0.113.50/32", "emerging_threats", "Known scanner IP")
	_ = bartTable.InsertCIDR("198.51.100.0/24", "tor_exit_nodes", "Tor exit relay")

	// C. GeoIP Reader with static overrides for deterministic testing
	geoReader := acl.NewNoopGeoIPReader()
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.10"), acl.GeoData{Country: "KP", ASN: 1234})  // Blocked country
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.20"), acl.GeoData{Country: "US", ASN: 15169}) // Allowed country
	geoReader.SetStaticLookup(net.ParseIP("192.0.2.30"), acl.GeoData{Country: "DE", ASN: 3320})  // Other country

	// D. Compiled Bytecode ACL Engine
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

	// E. Pre-Application Authentication Gateway
	sessionSecret := "testing-e2e-session-secret-32-bytes!"
	sessionMgr := auth.NewSessionManager(sessionSecret, auth.WithCookieTTL(2*time.Hour))
	simpleAuth := auth.NewSimpleAuth(auth.SimpleUser{
		Username:     "alice",
		PasswordHash: "secretpass123",
		Email:        "alice@corp.internal",
		Name:         "Alice Smith",
		Roles:        []string{"admin", "developer"},
	})
	authGateway := auth.NewAuthGateway(auth.GatewayConfig{
		SimpleAuth:  simpleAuth,
		SessionMgr:  sessionMgr,
		BypassPaths: []string{"/public/*", "/search", "/healthz", "/legacy*"},
	})

	// 3. Build Middleware
	semEngine := engine.NewSemanticEngine(engine.WithExceptionEngine(exEngine))

	mw := &proxy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}
	mw.SetExceptionEngine(exEngine)
	mw.SetBARTTable(bartTable)
	mw.SetGeoIPReader(geoReader)
	mw.SetACLEngine(aclEngine)
	mw.SetAuthGateway(authGateway)
	mw.SetEngine(semEngine)

	next := &e2eNextHandler{handler: backendMux}

	// ------------------------------------------------------------------
	// Scenario 1: Parameter Whitelist Bypass vs Adjacent Attack Block
	// ------------------------------------------------------------------
	t.Run("Parameter Exception Gate: Whitelisted vs Adjacent Attack", func(t *testing.T) {
		// A. Whitelisted parameter 'q' on /search containing SQLi tautology passes
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+OR+%271%27%3D%271", nil)
		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected whitelisted parameter to pass (200), got %d", rec.Code)
		}

		// B. Malicious attack in non-whitelisted parameter 'filter' on /search is blocked (403)
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/search?filter=%27+OR+%271%27%3D%271", nil)
		rec2 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec2, req2, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusForbidden {
			t.Errorf("expected adjacent malicious parameter to be blocked (403), got %d", rec2.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 2: Threat Feed IP Matching in BART Table
	// ------------------------------------------------------------------
	t.Run("BART Threat Feed Fast-Path Ban", func(t *testing.T) {
		// A. Malicious IP in feed is blocked immediately
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/status", nil)
		req.RemoteAddr = "203.0.113.50:4321" // Matches emerging_threats
		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected threat feed IP to be blocked (403), got %d", rec.Code)
		}
		if rec.Header().Get("X-Raiwall-Event-ID") == "" {
			t.Error("expected X-Raiwall-Event-ID header on blocked threat feed request")
		}

		// B. Clean IP passes
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/public/status", nil)
		req2.RemoteAddr = "192.0.2.100:4321" // Clean IP
		rec2 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec2, req2, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusOK {
			t.Errorf("expected clean IP to pass (200), got %d", rec2.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 3: GeoIP Country Fencing
	// ------------------------------------------------------------------
	t.Run("GeoIP Country Fencing", func(t *testing.T) {
		// A. Blocked country (KP) receives 451
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/content", nil)
		req.RemoteAddr = "192.0.2.10:1234" // Mapped to Country: "KP"
		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != 451 {
			t.Errorf("expected GeoIP blocked country to receive 451, got %d", rec.Code)
		}

		// B. Allowed country (US) passes
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/public/content", nil)
		req2.RemoteAddr = "192.0.2.20:1234" // Mapped to Country: "US"
		rec2 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec2, req2, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusOK {
			t.Errorf("expected allowed country to pass (200), got %d", rec2.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 4: Bytecode expr Complex Multi-Condition Rules
	// ------------------------------------------------------------------
	t.Run("Multi-Condition Bytecode Evaluation", func(t *testing.T) {
		// Rule: has_prefix(path, "/api/admin") && (headers["x-admin-key"] != "supersecret" || geo.Country != "US") -> Block 403
		cookie, _ := sessionMgr.CreateSessionCookie(&auth.UserIdentity{Subject: "alice"})

		// A. Missing header -> Blocked (403)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req.RemoteAddr = "192.0.2.20:5678" // US
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected missing admin key to be blocked (403), got %d", rec.Code)
		}

		// B. Valid header but wrong country (DE) -> Blocked (403)
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req2.RemoteAddr = "192.0.2.30:5678" // DE
		req2.Header.Set("X-Admin-Key", "supersecret")
		req2.AddCookie(cookie)
		rec2 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec2, req2, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec2.Code != http.StatusForbidden {
			t.Errorf("expected admin request from non-US country to be blocked (403), got %d", rec2.Code)
		}

		// C. Valid header AND correct country (US) -> Allowed (200)
		req3 := httptest.NewRequest(http.MethodGet, "http://example.com/api/admin/users", nil)
		req3.RemoteAddr = "192.0.2.20:5678" // US
		req3.Header.Set("X-Admin-Key", "supersecret")
		req3.AddCookie(cookie)

		rec3 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec3, req3, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec3.Code != http.StatusOK {
			t.Errorf("expected valid multi-condition request to pass (200), got %d", rec3.Code)
		}
	})

	// ------------------------------------------------------------------
	// Scenario 5: Pre-Application Auth Gateway Redirection & 401
	// ------------------------------------------------------------------
	t.Run("Pre-App Auth Redirection & API 401", func(t *testing.T) {
		// A. Unauthenticated browser request redirects to login
		req := httptest.NewRequest(http.MethodGet, "http://example.com/private/dashboard", nil)
		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("expected browser redirect (302), got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/.raiwall/auth/login") {
			t.Errorf("expected redirect to /.raiwall/auth/login, got %q", loc)
		}

		// B. Unauthenticated API request returns 401 JSON
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/api/private/metrics", nil)
		req2.Header.Set("Accept", "application/json")
		rec2 := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec2, req2, next); err != nil {
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

	// ------------------------------------------------------------------
	// Scenario 6: Authenticated Session with Upstream Identity Injection
	// ------------------------------------------------------------------
	t.Run("Authenticated Session and Upstream Identity Header Injection", func(t *testing.T) {
		cookie, err := sessionMgr.CreateSessionCookie(&auth.UserIdentity{
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
		req.Header.Set("X-Auth-Subject", "evil-spoofed-subject") // Client attempting to spoof identity
		req.Header.Set("X-Auth-Roles", "super-root")

		rec := httptest.NewRecorder()
		if err := mw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected authenticated request to pass (200), got %d", rec.Code)
		}

		// Inspect headers received by upstream backend
		val, ok := lastReceivedHeaders.Load("/private/profile")
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

	// ------------------------------------------------------------------
	// Scenario 7: Concurrent High-Load Verification (-race safety)
	// ------------------------------------------------------------------
	t.Run("Concurrent Access Control Under Load", func(t *testing.T) {
		const concurrency = 20
		const requestsPerGoroutine = 50

		cookie, err := sessionMgr.CreateSessionCookie(&auth.UserIdentity{
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
						// Whitelisted search
						req = httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+OR+%271%27%3D%271", nil)
					} else if j%4 == 1 {
						// Blocked threat feed
						req = httptest.NewRequest(http.MethodGet, "http://example.com/public/feed", nil)
						req.RemoteAddr = "203.0.113.50:1111"
					} else if j%4 == 2 {
						// Blocked country
						req = httptest.NewRequest(http.MethodGet, "http://example.com/public/geo", nil)
						req.RemoteAddr = "192.0.2.10:2222"
					} else {
						// Authenticated route
						req = httptest.NewRequest(http.MethodGet, "http://example.com/private/data", nil)
						req.AddCookie(cookie)
					}

					rec := httptest.NewRecorder()
					_ = mw.ServeHTTP(rec, req, next)
				}
			}(i)
		}

		wg.Wait()
	})
}
