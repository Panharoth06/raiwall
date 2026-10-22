package templates

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateManager_DefaultsAndRender(t *testing.T) {
	mgr := NewTemplateManager()
	require.NotNil(t, mgr)

	// Verify all 9 deterministic status codes exist
	codes := []int{403, 404, 429, 465, 466, 467, 468, 502, 504}
	for _, code := range codes {
		tmpl, err := mgr.GetTemplate(code)
		require.NoError(t, err, "status %d should exist", code)
		assert.Equal(t, code, tmpl.StatusCode)
		assert.False(t, tmpl.IsCustom)
		assert.NotEmpty(t, tmpl.Title)
		assert.NotEmpty(t, tmpl.ContentHTML)
	}

	// Test 403 rendering with variable substitution
	data := TemplateData{
		EventID:   "evt-12345",
		ClientIP:  "198.51.100.99",
		Timestamp: "2026-10-22T10:00:00Z",
		Host:      "secure.example.com",
		BrandName: "CyberShield",
	}

	rendered, err := mgr.Render(http.StatusForbidden, data)
	require.NoError(t, err)
	assert.Contains(t, rendered, "evt-12345")
	assert.Contains(t, rendered, "198.51.100.99")
	assert.Contains(t, rendered, "CyberShield")
	assert.Contains(t, rendered, "secure.example.com")
	assert.Contains(t, rendered, "HTTP 403")
}

func TestTemplateManager_CustomTemplateAndReset(t *testing.T) {
	mgr := NewTemplateManager()

	customHTML := `<html><body><h1>Custom Blocked: {{.EventID}}</h1><p>{{.BrandName}}</p></body></html>`
	customCSS := `body { background: black; }`

	tmpl, err := mgr.SetCustomTemplate(403, "Custom 403", customHTML, customCSS, "MyBrand", "")
	require.NoError(t, err)
	assert.True(t, tmpl.IsCustom)

	// Render custom
	rendered, err := mgr.Render(403, TemplateData{
		EventID:   "custom-ev-1",
		BrandName: "MyBrand",
	})
	require.NoError(t, err)
	assert.Contains(t, rendered, "Custom Blocked: custom-ev-1")
	assert.Contains(t, rendered, "MyBrand")

	// Reset to default
	resetted, err := mgr.ResetTemplate(403)
	require.NoError(t, err)
	assert.False(t, resetted.IsCustom)

	renderedDefault, err := mgr.Render(403, TemplateData{
		EventID: "default-ev-2",
	})
	require.NoError(t, err)
	assert.Contains(t, renderedDefault, "default-ev-2")
	assert.Contains(t, renderedDefault, "Security Violation Detected")
}

func TestTemplateManager_RenderPreview(t *testing.T) {
	mgr := NewTemplateManager()
	preview := mgr.RenderPreview(403, "", "", "PreviewBrand", "")
	assert.Contains(t, preview, "PreviewBrand")
	assert.Contains(t, preview, "203.0.113.195")
	assert.True(t, strings.HasPrefix(preview, "<!DOCTYPE html>"))
}
