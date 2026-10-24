package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_DeterministicTemplateRendering(t *testing.T) {
	m := &Middleware{
		Mode: "defense",
	}
	err := m.Provision(caddy.Context{Context: context.Background()})
	require.NoError(t, err)

	mockEng := waf.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		return &waf.Verdict{
			Action:     waf.ActionBlock,
			RuleID:     "TEST_BLOCK",
			StatusCode: 403,
			Reason:     "deterministic test block",
		}, nil
	}
	m.SetEngine(mockEng)

	// 1. Verify default 403 template renders
	req := httptest.NewRequest(http.MethodGet, "/test-target", nil)
	req.RemoteAddr = "198.51.100.42:12345"
	rec := httptest.NewRecorder()

	mockH := &mockHandler{}
	err = m.ServeHTTP(rec, req, mockH)
	require.NoError(t, err)
	assert.Equal(t, 403, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Request Blocked")
	assert.Contains(t, body, "198.51.100.42")
	eventID := rec.Header().Get("X-Raiwall-Event-ID")
	assert.NotEmpty(t, eventID)
	assert.Contains(t, body, eventID)

	// 2. Set custom 403 template in TemplateManager
	customHTML := `<!DOCTYPE html><html><head><style>{{.CustomCSS}}</style></head><body><div class="custom-block"><h1>Access Denied by {{.BrandName}}</h1><p>ID: {{.EventID}}</p><p>IP: {{.ClientIP}}</p></div></body></html>`
	customCSS := `.custom-block { color: red; }`
	_, err = m.TemplateManager().SetCustomTemplate(403, "Custom Forbidden", customHTML, customCSS, "AcmeCorp", "")
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodGet, "/test-target-custom", nil)
	req2.RemoteAddr = "203.0.113.88:54321"
	rec2 := httptest.NewRecorder()

	err = m.ServeHTTP(rec2, req2, mockH)
	require.NoError(t, err)
	assert.Equal(t, 403, rec2.Code)
	body2 := rec2.Body.String()
	assert.Contains(t, body2, "Access Denied by AcmeCorp")
	assert.Contains(t, body2, ".custom-block { color: red; }")
	assert.Contains(t, body2, "203.0.113.88")
	eventID2 := rec2.Header().Get("X-Raiwall-Event-ID")
	assert.NotEmpty(t, eventID2)
	assert.Contains(t, body2, "ID: "+eventID2)
}

func TestMiddleware_OfflineModeTemplateRendering(t *testing.T) {
	m := &Middleware{
		Mode:              "offline",
		OfflineStatusCode: 466,
	}
	err := m.Provision(caddy.Context{Context: context.Background()})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.RemoteAddr = "198.51.100.50:54321"
	rec := httptest.NewRecorder()

	err = m.ServeHTTP(rec, req, &mockHandler{})
	require.NoError(t, err)
	assert.Equal(t, 466, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Service Offline for Maintenance")
	assert.Contains(t, body, "HTTP 466")
	assert.NotEmpty(t, rec.Header().Get("X-Raiwall-Event-ID"))
}
