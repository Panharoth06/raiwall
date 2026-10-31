package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func operatorRequest(server *Server, method, path string, cookie *http.Cookie, apiKey string, payload any) *httptest.ResponseRecorder {
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if apiKey != "" {
		req.Header.Set("X-Raiwall-Key", apiKey)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func decodeAdminUser(t *testing.T, rec *httptest.ResponseRecorder) adminUserResponse {
	t.Helper()
	var resp adminUserResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

func operatorTestServer(t *testing.T) (*Server, control.ControlStore, *http.Cookie) {
	t.Helper()
	server, store := setupTestServer(t)
	secureSessionServer(t, server)
	createOperator(t, store, "root", "correct-horse-battery", RoleAdmin)
	cookie := login(t, server, "root", "correct-horse-battery")
	return server, store, cookie
}

func TestOperatorManagementRequiresAdmin(t *testing.T) {
	server, store, _ := operatorTestServer(t)
	defer store.Close()
	createOperator(t, store, "viewer", "correct-horse-battery", RoleViewer)
	viewerCookie := login(t, server, "viewer", "correct-horse-battery")

	list := operatorRequest(server, http.MethodGet, "/api/v1/users", viewerCookie, "", nil)
	require.Equal(t, http.StatusForbidden, list.Code)
	require.Contains(t, list.Body.String(), "requires admin")
}

func TestCreateOperatorGeneratesPasswordOnce(t *testing.T) {
	server, store, cookie := operatorTestServer(t)
	defer store.Close()

	rec := operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", map[string]any{
		"username": "alice",
		"role":     RoleViewer,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	resp := decodeAdminUser(t, rec)
	require.Equal(t, "alice", resp.User.Username)
	require.Equal(t, RoleViewer, resp.User.Role)
	require.True(t, resp.User.IsActive)
	require.NotEmpty(t, resp.Password, "a generated password must be returned once")

	login(t, server, "alice", resp.Password)

	list := operatorRequest(server, http.MethodGet, "/api/v1/users", cookie, "", nil)
	require.Equal(t, http.StatusOK, list.Code)
	var users []AdminUserDTO
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &users))
	found := false
	for _, user := range users {
		if user.Username == "alice" {
			found = true
		}
		require.NotContains(t, user.Username, "$2a$")
	}
	require.True(t, found)

	duplicate := operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", map[string]any{
		"username": "alice", "password": "another-strong-password",
	})
	require.Equal(t, http.StatusConflict, duplicate.Code)
}

func TestUpdateOperatorRevokesSessionsAndEnforcesGuards(t *testing.T) {
	server, store, cookie := operatorTestServer(t)
	defer store.Close()

	created := decodeAdminUser(t, operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", map[string]any{
		"username": "bob", "password": "bob-strong-password", "role": RoleAdmin,
	}))
	bobCookie := login(t, server, "bob", "bob-strong-password")

	demote := operatorRequest(server, http.MethodPatch, "/api/v1/users/"+created.User.ID, cookie, "", map[string]any{
		"role": RoleViewer,
	})
	require.Equal(t, http.StatusOK, demote.Code, demote.Body.String())
	require.Equal(t, RoleViewer, decodeAdminUser(t, demote).User.Role)

	stale := operatorRequest(server, http.MethodGet, "/api/v1/auth/me", bobCookie, "", nil)
	require.Equal(t, http.StatusUnauthorized, stale.Code, "role change must revoke sessions")

	root, err := store.GetUserByUsername(context.Background(), "root")
	require.NoError(t, err)
	self := operatorRequest(server, http.MethodPatch, "/api/v1/users/"+root.ID, cookie, "", map[string]any{
		"role": RoleViewer,
	})
	require.Equal(t, http.StatusConflict, self.Code)
}

func TestLastAdminCannotBeRemovedViaAPIKey(t *testing.T) {
	server, store, _ := operatorTestServer(t)
	defer store.Close()

	root, err := store.GetUserByUsername(context.Background(), "root")
	require.NoError(t, err)
	token := "rw_test_admin_key"
	require.NoError(t, store.CreateAPIKey(context.Background(), control.ApiKeyRecord{
		ID: "key-admin", Name: "automation", KeyHash: HashAPIKey(token), Role: RoleAdmin,
		IsActive: 1, CreatedAt: time.Now().UTC(),
	}))

	rec := operatorRequest(server, http.MethodDelete, "/api/v1/users/"+root.ID, nil, token, nil)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "at least one active admin")
}

func TestDeactivateAndResetPassword(t *testing.T) {
	server, store, cookie := operatorTestServer(t)
	defer store.Close()

	created := decodeAdminUser(t, operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", map[string]any{
		"username": "carol", "password": "carol-strong-password", "role": RoleViewer,
	}))
	carolCookie := login(t, server, "carol", "carol-strong-password")

	reset := operatorRequest(server, http.MethodPost, "/api/v1/users/"+created.User.ID+"/password", cookie, "", map[string]any{})
	require.Equal(t, http.StatusOK, reset.Code, reset.Body.String())
	newPassword := decodeAdminUser(t, reset).Password
	require.NotEmpty(t, newPassword)

	stale := operatorRequest(server, http.MethodGet, "/api/v1/auth/me", carolCookie, "", nil)
	require.Equal(t, http.StatusUnauthorized, stale.Code, "password reset must revoke sessions")
	login(t, server, "carol", newPassword)

	deactivate := operatorRequest(server, http.MethodDelete, "/api/v1/users/"+created.User.ID, cookie, "", nil)
	require.Equal(t, http.StatusOK, deactivate.Code, deactivate.Body.String())
	require.False(t, decodeAdminUser(t, deactivate).User.IsActive)

	body, _ := json.Marshal(map[string]string{"username": "carol", "password": newPassword})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a deactivated operator cannot log in")
}

func TestCreateOperatorValidation(t *testing.T) {
	server, store, cookie := operatorTestServer(t)
	defer store.Close()

	cases := []map[string]any{
		{"username": "ab", "password": "long-enough-password"},
		{"username": "bad name", "password": "long-enough-password"},
		{"username": "okname", "password": "short"},
		{"username": "okname", "password": "long-enough-password", "role": "owner"},
	}
	for _, payload := range cases {
		rec := operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", payload)
		require.Equal(t, http.StatusBadRequest, rec.Code, "payload %v", payload)
	}
}
