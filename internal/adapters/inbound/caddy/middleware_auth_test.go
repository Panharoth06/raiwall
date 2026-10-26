package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// TestMiddleware_GlobalAuthGate_ServeHTTP proves the global `auth` block is
// served by the same HTTP 467 portal as per-site auth.
func TestMiddleware_GlobalAuthGate_ServeHTTP(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := &Middleware{
		Mode: "defense",
		AuthConfig: &AuthSettings{
			Provider: "simple",
			Users: []auth.SimpleUser{{
				Username:     "alice",
				PasswordHash: "secretpass",
				Email:        "alice@example.com",
				Roles:        []string{"admin", "editor"},
			}},
			SessionSecret: "testing-session-secret-key-32-chars!!",
			SessionTTL:    caddyv2.Duration(1 * time.Hour),
			BypassPaths:   []string{"/public/*", "/healthz"},
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	require.NoError(t, mw.Provision(caddyCtx))

	gate := mw.GlobalAuthGate()
	require.NotNil(t, gate, "auth configuration block must compile into the shared portal")

	t.Run("Browser unauthenticated receives the single 467 portal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/dashboard", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.False(t, next.invoked)
		require.Equal(t, auth.ChallengeStatusCode, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "Raiwall Identity Gateway")
		require.Contains(t, rec.Body.String(), auth.AppAuthLoginPath)
	})

	t.Run("Legacy login route redirects to the portal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+auth.LegacyAuthLoginPath+"?redirect=%2Fdashboard", nil)
		rec := httptest.NewRecorder()
		require.NoError(t, mw.ServeHTTP(rec, req, &mockNextHandler{}))
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, auth.AppAuthLoginPath+"?redirect=%2Fdashboard", rec.Header().Get("Location"))
	})

	t.Run("API unauthenticated returns 401 JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/data", nil)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.False(t, next.invoked)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		var resp map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Equal(t, "unauthorized", resp["error"])
		require.Equal(t, auth.AppAuthLoginPath, resp["login_url"])
	})

	t.Run("Bypass path passes through and strips untrusted headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public/about", nil)
		req.Header.Set("X-Auth-Subject", "hacker")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.True(t, next.invoked)
		require.Empty(t, next.receivedHead.Get(auth.HeaderAuthSubject))
	})

	t.Run("Authenticated session injects identity headers upstream", func(t *testing.T) {
		cookie, err := gate.SessionManager().CreateSessionCookie(&auth.UserIdentity{
			Subject: "alice",
			Email:   "alice@example.com",
			Name:    "Alice Admin",
			Roles:   []string{"admin", "editor"},
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/dashboard", nil)
		req.AddCookie(cookie)
		req.Header.Set("X-Auth-Subject", "spoofed")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.True(t, next.invoked)
		require.Equal(t, "alice", next.receivedHead.Get(auth.HeaderAuthSubject))
		require.Equal(t, "alice@example.com", next.receivedHead.Get(auth.HeaderAuthEmail))
		require.Equal(t, "admin,editor", next.receivedHead.Get(auth.HeaderAuthRoles))
	})

	t.Run("Login endpoint renders the portal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+auth.AppAuthLoginPath, nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.False(t, next.invoked)
		require.Equal(t, auth.ChallengeStatusCode, rec.Code)
		require.Contains(t, rec.Body.String(), "Authentication required")
	})

	t.Run("Simple user login issues the unified clearance cookie", func(t *testing.T) {
		form := url.Values{"username": {"alice"}, "password": {"secretpass"}, "redirect": {"/dashboard"}}
		req := httptest.NewRequest(http.MethodPost, "http://example.com"+auth.AppAuthLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		require.NoError(t, mw.ServeHTTP(rec, req, &mockNextHandler{}))
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		require.Equal(t, "/dashboard", rec.Header().Get("Location"))
		require.Len(t, cookiesNamed(rec, auth.AppAuthCookieName), 1)
	})
}

// TestMiddleware_GlobalAuthGate_DirectoryLogin proves the portal-wide
// gate authenticates identity-directory accounts, not just simple users.
func TestMiddleware_GlobalAuthGate_DirectoryLogin(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(101, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	store, err := sqlite.InitDB(fmt.Sprintf("file:test_global_auth_%d.db", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	hash, err := auth.HashPassword("DirectoryPass123!")
	require.NoError(t, err)
	require.NoError(t, store.UpsertIdentityUser(context.Background(), control.IdentityUserRecord{
		ID:           "idusr-globaltest",
		Username:     "dana",
		PasswordHash: hash,
		Enabled:      1,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	mw := &Middleware{
		Mode:         "defense",
		controlStore: store,
		AuthConfig: &AuthSettings{
			Provider:      "simple",
			SessionSecret: "testing-session-secret-key-32-chars!!",
			SessionTTL:    caddyv2.Duration(1 * time.Hour),
		},
	}
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	require.NoError(t, mw.Provision(caddyCtx))
	require.NotNil(t, mw.GlobalAuthGate())

	form := url.Values{"username": {"dana"}, "password": {"DirectoryPass123!"}, "redirect": {"/dashboard"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com"+auth.AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	require.NoError(t, mw.ServeHTTP(rec, req, &mockNextHandler{}))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/dashboard", rec.Header().Get("Location"))
	clearance := cookiesNamed(rec, auth.AppAuthCookieName)
	require.Len(t, clearance, 1)

	// A cookie minted by the portal-wide gate must be accepted by a per-site
	// gate: both modes share the persisted clearance secret.
	persisted, err := store.GetSetting(context.Background(), "app_auth_session_secret")
	require.NoError(t, err)
	require.NotEmpty(t, persisted)
	snap := control.NewConfigSnapshot(102, control.ModeDefense, []*control.AppConfig{{
		ID:          "site-globaltest",
		Name:        "Global Test Site",
		Hostnames:   []string{"app.example.com"},
		Mode:        control.ModeDefense,
		AuthEnabled: true,
	}})
	snap.AppAuthSessionSecret = persisted
	control.StoreSnapshot(snap)

	siteReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	siteReq.AddCookie(clearance[0])
	siteRec := httptest.NewRecorder()
	next := &mockNextHandler{}
	require.NoError(t, mw.ServeHTTP(siteRec, siteReq, next))
	require.True(t, next.invoked, "per-site gate must accept the portal-wide clearance cookie")
	require.Equal(t, "dana", next.receivedHead.Get(auth.HeaderAuthSubject))
}
