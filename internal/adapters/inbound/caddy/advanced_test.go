package caddy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestAdvancedProxySettings(t *testing.T) {
	app := &control.AppConfig{
		ID:        "app-advanced",
		Name:      "Advanced App",
		Hostnames: []string{"secure.example.com"},
		Mode:      control.ModeDefense,
		ProxySettings: &control.ProxySettings{
			ClientIPSource: "X-Real-IP",
			RewriteXFF:     true,
			HSTS:           true,
			EnableSSE:      true,
			RedirectHTTP:   true,
		},
	}

	snap := control.NewConfigSnapshot(11, control.ModeDefense, []*control.AppConfig{app})
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := &Middleware{
		Mode:   "defense",
		engine: waf.NewSemanticEngine(),
	}

	t.Run("RedirectHTTP redirects HTTP to HTTPS with 301 Moved Permanently", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://secure.example.com/login", nil)
		req.Header.Set("X-Forwarded-Proto", "http")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.False(t, next.invoked, "should redirect before calling next")
		require.Equal(t, http.StatusMovedPermanently, rec.Code)
		require.Equal(t, "https://secure.example.com/login", rec.Header().Get("Location"))
	})

	t.Run("Client IP source extracts from configured header and rewrites XFF", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://secure.example.com/dashboard", nil)
		req.TLS = &tls.ConnectionState{} // simulate HTTPS
		req.Header.Set("X-Real-IP", "198.51.100.42")
		req.Header.Set("X-Forwarded-For", "untrusted.attacker.ip, 10.0.0.1")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.True(t, next.invoked)
		// Upstream received rewritten XFF with only trusted client IP
		require.Equal(t, "198.51.100.42", next.receivedHead.Get("X-Forwarded-For"))
	})

	t.Run("HSTS header is injected on HTTPS responses", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://secure.example.com/api/data", nil)
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.Equal(t, "max-age=31536000; includeSubDomains; preload", rec.Header().Get("Strict-Transport-Security"))
	})

	t.Run("SSE streaming disables proxy buffering when Accept: text/event-stream", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://secure.example.com/v1/chat/completions", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.Equal(t, "no", rec.Header().Get("X-Accel-Buffering"))
		require.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	})

	t.Run("Accept-Encoding is stripped upstream when compression is off", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://secure.example.com/data", nil)
		// RedirectHTTP is enabled on this app; move past the 301 by faking the
		// forwarded proto as https.
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("Accept-Encoding", "gzip, br")
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.True(t, next.invoked)
		require.Empty(t, next.receivedHead.Values("Accept-Encoding"),
			"uncompressed upstream bodies keep WAF inspection lossless")
	})
}

// TestCompressionPassThrough proves per-site compression keeps the client's
// native encoding upstream when explicitly opted in.
func TestCompressionPassThrough(t *testing.T) {
	app := &control.AppConfig{
		ID:        "app-compression",
		Name:      "Compression App",
		Hostnames: []string{"comp.example.com"},
		Mode:      control.ModeDefense,
		ProxySettings: &control.ProxySettings{
			EnableCompression: true,
		},
	}
	snap := control.NewConfigSnapshot(12, control.ModeDefense, []*control.AppConfig{app})
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := &Middleware{Mode: "defense", engine: waf.NewSemanticEngine()}

	req := httptest.NewRequest(http.MethodGet, "https://comp.example.com/assets/bundle.js", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	require.NoError(t, mw.ServeHTTP(rec, req, next))
	require.True(t, next.invoked)
	require.Equal(t, "gzip, br", next.receivedHead.Get("Accept-Encoding"))
}
