package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAPI_CreateAPIKeyRejectsUnknownRole prevents free-form role strings (for
// example "superadmin") from being persisted and later evaluated by RBAC.
func TestAPI_CreateAPIKeyRejectsUnknownRole(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_apikey_role"
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken)))

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/apikeys", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusBadRequest, post(`{"name":"bad","role":"superadmin"}`).Code)
	require.Equal(t, http.StatusCreated, post(`{"name":"viewer key","role":"viewer"}`).Code)
}
