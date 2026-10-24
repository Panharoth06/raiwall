package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouteClassifier(t *testing.T) {
	classifier := NewRouteClassifier(nil)

	tests := []struct {
		name       string
		path       string
		headers    map[string]string
		wantRoute  RouteType
		wantBypass bool
	}{
		{
			name:       "API Path Prefix /api/v1/users",
			path:       "/api/v1/users",
			headers:    nil,
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "API Path Prefix /graphql",
			path:       "/graphql",
			headers:    nil,
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "API Path Prefix /webhooks/stripe",
			path:       "/webhooks/stripe",
			headers:    nil,
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "Bearer Token on Non-API Path",
			path:       "/checkout/process",
			headers:    map[string]string{"Authorization": "Bearer eyJhbGciOi..."},
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "API Key Header",
			path:       "/data/export",
			headers:    map[string]string{"X-API-Key": "secret-key-123"},
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "Accept application/json",
			path:       "/users/me",
			headers:    map[string]string{"Accept": "application/json"},
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "Content-Type application/json",
			path:       "/items",
			headers:    map[string]string{"Content-Type": "application/json"},
			wantRoute:  RouteAPI,
			wantBypass: true,
		},
		{
			name:       "Static Asset Javascript",
			path:       "/assets/index-b4f8d.js",
			headers:    nil,
			wantRoute:  RouteStatic,
			wantBypass: true,
		},
		{
			name:       "Static Asset Image SVG",
			path:       "/images/logo.svg",
			headers:    nil,
			wantRoute:  RouteStatic,
			wantBypass: true,
		},
		{
			name:       "Static Asset Font WOFF2",
			path:       "/fonts/inter.woff2",
			headers:    nil,
			wantRoute:  RouteStatic,
			wantBypass: true,
		},
		{
			name:       "Browser Navigation Root",
			path:       "/",
			headers:    map[string]string{"Accept": "text/html,application/xhtml+xml"},
			wantRoute:  RouteBrowser,
			wantBypass: false,
		},
		{
			name:       "Browser Navigation Login Page",
			path:       "/login",
			headers:    map[string]string{"Accept": "text/html"},
			wantRoute:  RouteBrowser,
			wantBypass: false,
		},
		{
			name:       "Browser Navigation Dashboard",
			path:       "/dashboard",
			headers:    map[string]string{"Accept": "*/*"},
			wantRoute:  RouteBrowser,
			wantBypass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com"+tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			gotRoute := classifier.Classify(req)
			if gotRoute != tt.wantRoute {
				t.Errorf("Classify() = %v, want %v", gotRoute, tt.wantRoute)
			}

			bypass := classifier.ShouldBypass(req)
			if bypass != tt.wantBypass {
				t.Errorf("ShouldBypass() = %v, want %v", bypass, tt.wantBypass)
			}
		})
	}
}

func TestCustomRouteConfig(t *testing.T) {
	customCfg := &RouteClassifierConfig{
		APIPrefixes:   []string{"/custom-api/"},
		BypassHeaders: []string{"X-Custom-Client"},
	}
	classifier := NewRouteClassifier(customCfg)

	req1 := httptest.NewRequest(http.MethodGet, "https://example.com/custom-api/status", nil)
	if classifier.Classify(req1) != RouteAPI {
		t.Errorf("Expected RouteAPI for /custom-api/status")
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/order", nil)
	req2.Header.Set("X-Custom-Client", "mobile-app")
	if classifier.Classify(req2) != RouteAPI {
		t.Errorf("Expected RouteAPI for X-Custom-Client header")
	}
}
