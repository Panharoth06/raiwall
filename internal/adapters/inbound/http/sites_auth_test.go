package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAPI_SiteAuthGateConfig proves the auth_enabled and auth_bypass_paths
// site fields round-trip through create/get/update.
func TestAPI_SiteAuthGateConfig(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_site_auth_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))
	do := func(method, path string, payload any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	// 1. Create with the gate enabled.
	rec := do(http.MethodPost, "/api/v1/sites", map[string]any{
		"name":              "Portal",
		"hostnames":         []string{"portal.corp.example"},
		"mode":              "defense",
		"auth_enabled":      true,
		"auth_bypass_paths": []string{"/health", "/assets"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created struct {
		ID              string   `json:"id"`
		AuthEnabled     bool     `json:"auth_enabled"`
		AuthBypassPaths []string `json:"auth_bypass_paths"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.True(t, created.AuthEnabled)
	require.Equal(t, []string{"/health", "/assets"}, created.AuthBypassPaths)

	// 2. GET returns the persisted state.
	rec = do(http.MethodGet, "/api/v1/sites/"+created.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.True(t, created.AuthEnabled)

	// 3. Update clears the gate.
	rec = do(http.MethodPut, "/api/v1/sites/"+created.ID, map[string]any{
		"name":              "Portal",
		"auth_enabled":      false,
		"auth_bypass_paths": []string{},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var updated struct {
		AuthEnabled     bool     `json:"auth_enabled"`
		AuthBypassPaths []string `json:"auth_bypass_paths"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.False(t, updated.AuthEnabled)
	require.Empty(t, updated.AuthBypassPaths)
}
