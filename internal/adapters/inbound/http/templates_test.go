package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_TemplatesCRUDAndPreview(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_templates_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	// 1. List Templates
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var list []TemplateDTO
	err := json.Unmarshal(w.Body.Bytes(), &list)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 9)

	// 2. Get 403 Template
	req = httptest.NewRequest(http.MethodGet, "/api/v1/templates/403", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var t403 TemplateDTO
	err = json.Unmarshal(w.Body.Bytes(), &t403)
	require.NoError(t, err)
	assert.Equal(t, 403, t403.StatusCode)
	assert.False(t, t403.IsCustom)

	// 3. Update 403 Template (custom branding & HTML)
	updatePayload, _ := json.Marshal(map[string]string{
		"title":        "Corporate Access Blocked",
		"content_html": "<!DOCTYPE html><html><body><h1>Corporate Block: {{.EventID}}</h1><p>{{.BrandName}}</p></body></html>",
		"custom_css":   "body { background: #000; }",
		"brand_name":   "Enterprise Corp",
		"logo_url":     "https://example.com/corp.png",
	})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/templates/403", bytes.NewReader(updatePayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var updated TemplateDTO
	err = json.Unmarshal(w.Body.Bytes(), &updated)
	require.NoError(t, err)
	assert.True(t, updated.IsCustom)
	assert.Equal(t, "Enterprise Corp", updated.BrandName)

	// 4. Preview Template
	previewPayload, _ := json.Marshal(map[string]string{
		"content_html": "<h1>Preview: {{.EventID}}</h1><span>{{.BrandName}}</span>",
		"custom_css":   "h1 { color: red; }",
		"brand_name":   "PreviewBrand",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/templates/403/preview", bytes.NewReader(previewPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var previewResp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &previewResp)
	require.NoError(t, err)
	assert.Contains(t, previewResp["rendered_html"], "PreviewBrand")

	// 5. Reset Template to Default
	req = httptest.NewRequest(http.MethodPost, "/api/v1/templates/403/reset", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resetted TemplateDTO
	err = json.Unmarshal(w.Body.Bytes(), &resetted)
	require.NoError(t, err)
	assert.False(t, resetted.IsCustom)
	assert.Equal(t, "Raiwall", resetted.BrandName)
}
