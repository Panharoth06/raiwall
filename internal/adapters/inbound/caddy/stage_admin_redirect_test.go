package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func adminRedirectMiddleware() *Middleware {
	return &Middleware{
		Mode:      "defense",
		engine:    waf.NewSemanticEngine(),
		uiHandler: &UIHandler{},
	}
}

func browserRequest(method, url string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return req
}

func TestRedirectUnconfiguredHostSendsBrowsersToDashboard(t *testing.T) {
	snap := control.NewConfigSnapshot(4, control.ModeDefense, []*control.AppConfig{
		{ID: "site-known", Name: "Known", Hostnames: []string{"app.example.com"}},
	})
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := adminRedirectMiddleware()

	t.Run("unknown host redirects to dashboard", func(t *testing.T) {
		req := browserRequest(http.MethodGet, "http://unconfigured.example.net/")
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, &mockNextHandler{})
		require.NoError(t, err)
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, adminDashboardPath, rec.Header().Get("Location"))
		require.Equal(t, "admin-redirect", rec.Header().Get("X-Raiwall-Route"))
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
			"redirect must not be cached so a later site on the same host is not shadowed")
	})

	t.Run("deep link without file extension redirects", func(t *testing.T) {
		req := browserRequest(http.MethodGet, "http://unconfigured.example.net/sites")
		rec := httptest.NewRecorder()

		require.NoError(t, mw.ServeHTTP(rec, req, &mockNextHandler{}))
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, adminDashboardPath, rec.Header().Get("Location"))
	})

	t.Run("HEAD navigation redirects without a body", func(t *testing.T) {
		req := browserRequest(http.MethodHead, "http://unconfigured.example.net/")
		rec := httptest.NewRecorder()

		require.NoError(t, mw.ServeHTTP(rec, req, &mockNextHandler{}))
		require.Equal(t, http.StatusFound, rec.Code)
		require.Empty(t, rec.Body.String())
	})

	t.Run("configured host is never redirected", func(t *testing.T) {
		req := browserRequest(http.MethodGet, "http://app.example.com/")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		require.NoError(t, mw.ServeHTTP(rec, req, next))
		require.NotEqual(t, http.StatusFound, rec.Code)
		require.NotEqual(t, adminDashboardPath, rec.Header().Get("Location"))
	})
}

func TestRedirectUnconfiguredHostIgnoresNonBrowserTraffic(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(4, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := adminRedirectMiddleware()

	cases := []struct {
		name   string
		method string
		url    string
		accept string
	}{
		{name: "curl wildcard accept", method: http.MethodGet, url: "http://unconfigured.example.net/", accept: "*/*"},
		{name: "json api client", method: http.MethodGet, url: "http://unconfigured.example.net/api/v1/sites", accept: "application/json"},
		{name: "no accept header", method: http.MethodGet, url: "http://unconfigured.example.net/"},
		{name: "post form", method: http.MethodPost, url: "http://unconfigured.example.net/login", accept: "text/html"},
		{name: "asset request", method: http.MethodGet, url: "http://unconfigured.example.net/favicon.ico", accept: "text/html"},
		{name: "acme http-01 token", method: http.MethodGet, url: "http://unconfigured.example.net/.well-known/acme-challenge/token", accept: "*/*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()

			require.False(t, mw.redirectUnconfiguredHost(rec, req))
			require.NotEqual(t, http.StatusFound, rec.Code)
		})
	}
}

func TestRedirectUnconfiguredHostRequiresSnapshotAndUI(t *testing.T) {
	t.Run("no active snapshot keeps gateway behaviour", func(t *testing.T) {
		control.StoreSnapshot(nil)
		t.Cleanup(func() {
			control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
		})

		req := browserRequest(http.MethodGet, "http://unconfigured.example.net/")
		rec := httptest.NewRecorder()

		require.NoError(t, adminRedirectMiddleware().ServeHTTP(rec, req, &mockNextHandler{}))
		require.NotEqual(t, http.StatusFound, rec.Code)
		require.NotEqual(t, adminDashboardPath, rec.Header().Get("Location"))
	})

	t.Run("missing embedded UI disables redirect", func(t *testing.T) {
		mw := &Middleware{Mode: "defense", engine: waf.NewSemanticEngine()}
		req := browserRequest(http.MethodGet, "http://unconfigured.example.net/")
		rec := httptest.NewRecorder()

		require.False(t, mw.redirectUnconfiguredHost(rec, req))
		require.NotEqual(t, http.StatusFound, rec.Code)
	})
}
