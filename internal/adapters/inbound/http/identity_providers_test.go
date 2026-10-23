package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAPI_IdentityProviderLifecycle covers create (with fail-fast config
// compile), list, update, and delete of external IdP connectors.
func TestAPI_IdentityProviderLifecycle(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_idp_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))
	do := func(method, path string, payload any) *httptest.ResponseRecorder {
		var body *bytes.Reader
		if payload == nil {
			body = bytes.NewReader(nil)
		} else {
			raw, _ := json.Marshal(payload)
			body = bytes.NewReader(raw)
		}
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	// 1. Create a GitHub connector.
	rec := do(http.MethodPost, "/api/v1/identity/providers", map[string]any{
		"type": "github",
		"name": "github-dirsso",
		"config": map[string]any{
			"client_id":     "cid",
			"client_secret": "csecret",
			"redirect_url":  "https://waf.corp.example/.raiwall/auth/callback",
		},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.Equal(t, "github", created.Type)
	require.True(t, created.Enabled)

	// 2. Invalid provider type is rejected.
	rec = do(http.MethodPost, "/api/v1/identity/providers", map[string]any{
		"type": "kerberos", "name": "x", "config": map[string]any{},
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// 3. Malformed backend config fails fast at save time (no broken IdPs).
	rec = do(http.MethodPost, "/api/v1/identity/providers", map[string]any{
		"type": "ldap", "name": "corp", "config": map[string]any{"host_url": "no-scheme"},
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// 4. 404 on unknown connector update.
	rec = do(http.MethodPut, "/api/v1/identity/providers/nope", map[string]any{"name": "y"})
	require.Equal(t, http.StatusNotFound, rec.Code)

	// 5. Update label and disable.
	rec = do(http.MethodPut, "/api/v1/identity/providers/"+created.ID, map[string]any{
		"name": "github-employee-sso", "enabled": false,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updated struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "github-employee-sso", updated.Name)
	require.False(t, updated.Enabled)

	// 6. List contains exactly the one connector.
	rec = do(http.MethodGet, "/api/v1/identity/providers", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listed []struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listed))
	require.Len(t, listed, 1)

	// 7. Delete then confirm it vanished.
	rec = do(http.MethodDelete, "/api/v1/identity/providers/"+created.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = do(http.MethodGet, "/api/v1/identity/providers", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listed))
	require.Empty(t, listed)
}
