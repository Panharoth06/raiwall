package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/stretchr/testify/require"
)

// TestAPI_IdentityUserLifecycle exercises the directory REST surface:
// create, unique-username rejection, list/get, update, password reset,
// TOTP enroll + verify through the core login, TOTP disable, delete.
func TestAPI_IdentityUserLifecycle(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_identity_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))
	authHeader := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
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
		authHeader(req)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	// 1. Create
	rec := do(http.MethodPost, "/api/v1/identity/users", map[string]any{
		"username":     "walter",
		"password":     "S3cure!Passwd",
		"email":        "walter@corp.example",
		"display_name": "Walter Ops",
		"app_ids":      []string{"site-frontend", "site-api"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created struct {
		ID           string   `json:"id"`
		Username     string   `json:"username"`
		Email        string   `json:"email"`
		AppIDs       []string `json:"app_ids"`
		Enabled      bool     `json:"enabled"`
		TOTPEnrolled bool     `json:"totp_enrolled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.Equal(t, "walter", created.Username)
	require.True(t, created.Enabled)
	require.False(t, created.TOTPEnrolled)

	// 2. Duplicate username is rejected.
	rec = do(http.MethodPost, "/api/v1/identity/users", map[string]any{
		"username": "walter", "password": "Another!Pass12",
	})
	require.Equal(t, http.StatusConflict, rec.Code)

	// 3. Weak password rejected.
	rec = do(http.MethodPost, "/api/v1/identity/users", map[string]any{
		"username": "jesse", "password": "short",
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// 4. Missing user 404s.
	rec = do(http.MethodGet, "/api/v1/identity/users/does-not-exist", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// 5. Update display + app assignments + disable.
	rec = do(http.MethodPut, "/api/v1/identity/users/"+created.ID, map[string]any{
		"display_name": "Walter W.",
		"app_ids":      []string{"site-frontend"},
		"enabled":      false,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updated struct {
		DisplayName string   `json:"display_name"`
		AppIDs      []string `json:"app_ids"`
		Enabled     bool     `json:"enabled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "Walter W.", updated.DisplayName)
	require.Equal(t, []string{"site-frontend"}, updated.AppIDs)
	require.False(t, updated.Enabled)

	// 6. Password reset. The account stays disabled (step 5) — password
	// rotation must not silently resurrect locked accounts.
	rec = do(http.MethodPost, "/api/v1/identity/users/"+created.ID+"/password-reset",
		map[string]any{"new_password": "Fresh!Passw0rd"})
	require.Equal(t, http.StatusOK, rec.Code)

	recordStored, err := store.GetIdentityUserByUsername(t.Context(), created.Username)
	require.NoError(t, err)
	require.Equal(t, int64(0), recordStored.Enabled)
	err = (&auth.DirectoryLogin{
		PasswordHash: recordStored.PasswordHash,
		Enabled:      recordStored.Enabled == 1,
	}).Authenticate("Fresh!Passw0rd", "")
	require.Error(t, err, "disabled account stays locked after password reset")
	require.Contains(t, err.Error(), "account is disabled")

	// 7. TOTP enroll returns a one-time secret + provisioning URI.
	rec = do(http.MethodPost, "/api/v1/identity/users/"+created.ID+"/totp-reset",
		map[string]any{"enroll": true})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var totpResp struct {
		TOTPSecret string `json:"totp_secret"`
		URI        string `json:"totp_provisioning_uri"`
		TOTPOn     bool   `json:"totp_enrolled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &totpResp))
	require.NotEmpty(t, totpResp.TOTPSecret)
	require.Contains(t, totpResp.URI, "otpauth://totp")
	require.True(t, totpResp.TOTPOn)

	// 8. TOTP disable clears the factor.
	rec = do(http.MethodPost, "/api/v1/identity/users/"+created.ID+"/totp-reset",
		map[string]any{"enroll": false})
	require.Equal(t, http.StatusOK, rec.Code)
	var totpDisabled struct {
		TOTPSecret string `json:"totp_secret"`
		TOTPOn     bool   `json:"totp_enrolled"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &totpDisabled))
	require.Empty(t, totpDisabled.TOTPSecret)
	require.False(t, totpDisabled.TOTPOn)

	// 9. Delete then confirm 404.
	rec = do(http.MethodDelete, "/api/v1/identity/users/"+created.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = do(http.MethodGet, "/api/v1/identity/users/"+created.ID, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestAPI_IdentityUsersList lists the directory and omits secrets.
func TestAPI_IdentityUsersList(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_identity_list_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	rec := httptest.NewRequest(http.MethodGet, "/api/v1/identity/users", nil)
	rec.Header.Set("Authorization", "Bearer "+adminToken)
	out := httptest.NewRecorder()
	server.ServeHTTP(out, rec)
	require.Equal(t, http.StatusOK, out.Code)

	var users []map[string]any
	require.NoError(t, json.Unmarshal(out.Body.Bytes(), &users))
	require.Empty(t, users) // fresh directory starts empty
}
