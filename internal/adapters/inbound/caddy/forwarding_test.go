package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestMatchForwardingRule(t *testing.T) {
	rules := []control.ForwardingRule{
		{
			Prefix:   "/api",
			IsActive: true,
			Upstreams: []control.UpstreamTarget{
				{Dial: "127.0.0.1:8001"},
			},
		},
		{
			Prefix:   "/api/v1/auth",
			IsActive: true,
			Upstreams: []control.UpstreamTarget{
				{Dial: "127.0.0.1:8002"},
			},
		},
		{
			Prefix:   "/static",
			IsActive: false, // inactive rule should be skipped
			Upstreams: []control.UpstreamTarget{
				{Dial: "127.0.0.1:8003"},
			},
		},
	}

	tests := []struct {
		name       string
		path       string
		wantPrefix string
		wantMatch  bool
	}{
		{
			name:       "exact match longer prefix",
			path:       "/api/v1/auth",
			wantPrefix: "/api/v1/auth",
			wantMatch:  true,
		},
		{
			name:       "subpath match longer prefix",
			path:       "/api/v1/auth/login",
			wantPrefix: "/api/v1/auth",
			wantMatch:  true,
		},
		{
			name:       "fallback to shorter active prefix",
			path:       "/api/v2/users",
			wantPrefix: "/api",
			wantMatch:  true,
		},
		{
			name:      "inactive rule returns no match",
			path:      "/static/logo.png",
			wantMatch: false,
		},
		{
			name:      "unmatched path returns nil",
			path:      "/home",
			wantMatch: false,
		},
		{
			name:      "partial segment prefix should not match /apigateway",
			path:      "/apigateway",
			wantMatch: false,
		},
		{
			name:      "sibling segment prefix should not match /api-v2/users",
			path:      "/api-v2/users",
			wantMatch: false,
		},
		{
			name:       "exact match prefix without trailing slash",
			path:       "/api",
			wantPrefix: "/api",
			wantMatch:  true,
		},
		{
			name:       "match prefix with trailing slash",
			path:       "/api/",
			wantPrefix: "/api",
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MatchForwardingRule(rules, tt.path)
			if !tt.wantMatch {
				require.Nil(t, m)
			} else {
				require.NotNil(t, m)
				require.Equal(t, tt.wantPrefix, m.Prefix)
			}
		})
	}
}

type testRoundTripper func(req *http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDynamicForwarding_ServeHTTP(t *testing.T) {
	var backend1ReceivedPath string
	var backend1ReceivedHost string
	var backend2ReceivedPath string

	b1Dial := "backend1.internal:8001"
	b2Dial := "backend2.internal:8002"

	registry := NewUpstreamRegistry()
	registry.SetTransport(testRoundTripper(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		if req.URL.Host == b1Dial {
			backend1ReceivedPath = req.URL.Path
			backend1ReceivedHost = req.Host
			rec.Header().Set("X-Backend", "b1")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte("backend1 response"))
		} else if req.URL.Host == b2Dial {
			backend2ReceivedPath = req.URL.Path
			rec.Header().Set("X-Backend", "b2")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte("backend2 response"))
		} else {
			rec.WriteHeader(http.StatusBadGateway)
		}
		return rec.Result(), nil
	}))

	app := &control.AppConfig{
		ID:        "app-test",
		Name:      "Test App",
		Hostnames: []string{"test.example.com"},
		Mode:      control.ModeDefense,
		Upstreams: []control.UpstreamTarget{
			{Dial: b2Dial, Weight: 1},
		},
		ForwardingRules: []control.ForwardingRule{
			{
				Prefix:             "/api/v1",
				StripPrefix:        true,
				HostHeaderOverride: "api-internal.local",
				IsActive:           true,
				Upstreams: []control.UpstreamTarget{
					{Dial: b1Dial, Weight: 1},
				},
			},
		},
	}

	snap := control.NewConfigSnapshot(10, control.ModeDefense, []*control.AppConfig{app})
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := &Middleware{
		Mode:             "defense",
		engine:           waf.NewSemanticEngine(),
		upstreamRegistry: registry,
	}
	t.Cleanup(func() {
		_ = mw.Cleanup()
	})

	t.Run("Routes to forwarding rule with strip prefix and host override", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://test.example.com/api/v1/users/list", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.False(t, next.invoked, "dynamic upstream should bypass next handler")
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "b1", rec.Header().Get("X-Backend"))
		require.Equal(t, "/users/list", backend1ReceivedPath, "prefix should be stripped")
		require.Equal(t, "api-internal.local", backend1ReceivedHost, "host header should be overridden")
	})

	t.Run("Routes to default app upstreams when no forwarding rule matches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://test.example.com/dashboard/home", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.False(t, next.invoked, "default upstream should bypass next handler")
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "b2", rec.Header().Get("X-Backend"))
		require.Equal(t, "/dashboard/home", backend2ReceivedPath)
	})

	t.Run("Falls back to next handler when no custom upstreams configured for host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://other.example.com/index.html", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		require.True(t, next.invoked, "should delegate to next.ServeHTTP")
		require.Equal(t, http.StatusOK, rec.Code)
	})
}
