package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) (*Server, *db.Store) {
	dsn := fmt.Sprintf("file:test_api_%d.db", time.Now().UnixNano())
	store, err := db.InitDB(dsn)
	require.NoError(t, err)

	server := NewServer(store, []byte("super-secret-hmac-key-for-tests-32b"))
	return server, store
}

func TestAuth_PublicDocsAndSpec(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	// 1. OpenAPI JSON Spec
	req := httptest.NewRequest(http.MethodGet, "/.raiwall/api/openapi.json", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"openapi":"3.1.0"`)

	// 2. Scalar Docs
	req = httptest.NewRequest(http.MethodGet, "/.raiwall/api/docs", nil)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `@scalar/api-reference`)
}

func TestAuth_LoginAndSessionCookie(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Seed admin user
	hash, err := HashPassword("SecretPass123!")
	require.NoError(t, err)

	err = store.CreateUser(ctx, db.CreateUserParams{
		ID:           "u-admin",
		Username:     "admin",
		PasswordHash: hash,
		Role:         RoleAdmin,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	// 1. Invalid Login
	body, _ := json.Marshal(LoginRequest{Username: "admin", Password: "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// 2. Valid Login
	body, _ = json.Marshal(LoginRequest{Username: "admin", Password: "SecretPass123!"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Check cookie
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie)

	// 3. Authenticated request using cookie
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"username":"admin"`)
	require.Contains(t, w.Body.String(), `"role":"admin"`)
}

func TestAuth_APIKeyAndRBAC(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Create admin key and viewer key
	adminToken := "rw_admin_test_token_12345678"
	viewerToken := "rw_viewer_test_token_87654321"

	err := store.CreateAPIKey(ctx, db.CreateAPIKeyParams{
		ID:        "key-admin",
		Name:      "Admin Key",
		KeyHash:   HashAPIKey(adminToken),
		Role:      RoleAdmin,
		IsActive:  1,
		CreatedAt: now,
	})
	require.NoError(t, err)

	err = store.CreateAPIKey(ctx, db.CreateAPIKeyParams{
		ID:        "key-viewer",
		Name:      "Viewer Key",
		KeyHash:   HashAPIKey(viewerToken),
		Role:      RoleViewer,
		IsActive:  1,
		CreatedAt: now,
	})
	require.NoError(t, err)

	// 1. Unauthenticated request to /api/v1/sites should return 401
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// 2. Viewer read request should succeed
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 3. Viewer mutate (POST) request should receive 403 Forbidden
	siteBody, _ := json.Marshal(SiteDTO{Name: "Forbidden Site", Hostnames: []string{"forbidden.com"}})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sites", bytes.NewReader(siteBody))
	req.Header.Set("X-Raiwall-Key", viewerToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Contains(t, w.Body.String(), "Forbidden: write operations require admin role")

	// 4. Admin mutate (POST) request should succeed
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sites", bytes.NewReader(siteBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	require.Contains(t, w.Body.String(), "Forbidden Site")
}
