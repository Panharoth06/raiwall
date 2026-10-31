package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func createOperator(t *testing.T, store control.ControlStore, username, password, role string) control.UserRecord {
	t.Helper()
	hash, err := HashPassword(password)
	require.NoError(t, err)
	now := time.Now().UTC()
	user := control.UserRecord{
		ID:           "u-" + username,
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, store.CreateUser(context.Background(), user))
	return user
}

func secureSessionServer(t *testing.T, server *Server) {
	t.Helper()
	server.SetSessionConfig(SessionConfig{
		IdleTimeout:     time.Hour,
		AbsoluteTimeout: 2 * time.Hour,
		Secure:          true,
		PublicURL:       "https://raiwall.example.com",
	})
}

func login(t *testing.T, server *Server, username, password string) *http.Cookie {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)
	return cookies[0]
}

func authedRequest(server *Server, method, path string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func TestLoginCreatesOpaqueSessionAndSecureCookie(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	secureSessionServer(t, server)
	user := createOperator(t, store, "alice", "correct-horse-battery", RoleAdmin)

	cookie := login(t, server, "alice", "correct-horse-battery")
	require.Equal(t, SecureSessionCookieName, cookie.Name)
	require.True(t, cookie.Secure)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	require.Equal(t, "/", cookie.Path)

	session, err := store.GetAdminSessionByTokenHash(context.Background(), server.AuthManager().hashToken(cookie.Value))
	require.NoError(t, err)
	require.Equal(t, user.ID, session.UserID)
	require.NotEqual(t, cookie.Value, session.TokenHash, "only the token hash may be stored")

	me := authedRequest(server, http.MethodGet, "/api/v1/auth/me", cookie, "")
	require.Equal(t, http.StatusOK, me.Code)
	var authCtx AuthContext
	require.NoError(t, json.Unmarshal(me.Body.Bytes(), &authCtx))
	require.Equal(t, "alice", authCtx.Username)
	require.Equal(t, RoleAdmin, authCtx.Role)
}

func TestSessionRevalidatesRoleAndActiveState(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	secureSessionServer(t, server)
	user := createOperator(t, store, "bob", "correct-horse-battery", RoleAdmin)

	cookie := login(t, server, "bob", "correct-horse-battery")

	user.Role = RoleViewer
	user.UpdatedAt = time.Now().UTC()
	require.NoError(t, store.UpdateUser(context.Background(), user))

	me := authedRequest(server, http.MethodGet, "/api/v1/auth/me", cookie, "https://raiwall.example.com")
	require.Equal(t, http.StatusOK, me.Code)
	var authCtx AuthContext
	require.NoError(t, json.Unmarshal(me.Body.Bytes(), &authCtx))
	require.Equal(t, RoleViewer, authCtx.Role, "role must come from the database")

	mutation := authedRequest(server, http.MethodPut, "/api/v1/system/auto-apply", cookie, "https://raiwall.example.com")
	require.Equal(t, http.StatusForbidden, mutation.Code, "demoted operator must lose write access immediately")

	user.IsActive = 0
	require.NoError(t, store.UpdateUser(context.Background(), user))
	me = authedRequest(server, http.MethodGet, "/api/v1/auth/me", cookie, "")
	require.Equal(t, http.StatusUnauthorized, me.Code)
}

func TestLogoutRevokesSession(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	secureSessionServer(t, server)
	createOperator(t, store, "carol", "correct-horse-battery", RoleAdmin)

	cookie := login(t, server, "carol", "correct-horse-battery")
	out := authedRequest(server, http.MethodPost, "/api/v1/auth/logout", cookie, "")
	require.Equal(t, http.StatusOK, out.Code)

	me := authedRequest(server, http.MethodGet, "/api/v1/auth/me", cookie, "")
	require.Equal(t, http.StatusUnauthorized, me.Code, "a revoked cookie must not authenticate")
}

func TestCSRFRejectsCrossOriginCookieMutation(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	secureSessionServer(t, server)
	createOperator(t, store, "dave", "correct-horse-battery", RoleAdmin)
	cookie := login(t, server, "dave", "correct-horse-battery")

	cross := authedRequest(server, http.MethodPut, "/api/v1/system/auto-apply", cookie, "https://evil.example")
	require.Equal(t, http.StatusForbidden, cross.Code)
	require.Contains(t, cross.Body.String(), "cross-origin")

	sameReq := httptest.NewRequest(http.MethodPut, "/api/v1/system/auto-apply", bytes.NewReader([]byte(`{"auto_apply":true}`)))
	sameReq.AddCookie(cookie)
	sameReq.Header.Set("Origin", "https://raiwall.example.com")
	same := httptest.NewRecorder()
	server.ServeHTTP(same, sameReq)
	require.Equal(t, http.StatusOK, same.Code)
}

func TestLoginThrottlesAndLocksOut(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	createOperator(t, store, "erin", "correct-horse-battery", RoleAdmin)

	for i := 0; i < loginMaxFailures; i++ {
		body, _ := json.Marshal(map[string]string{"username": "erin", "password": "wrong"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code, "attempt %d", i+1)
	}

	body, _ := json.Marshal(map[string]string{"username": "erin", "password": "correct-horse-battery"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	retry, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err)
	require.Greater(t, retry, 0)
}

func TestBasicAuthIsDisabledByDefault(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	createOperator(t, store, "frank", "correct-horse-battery", RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.SetBasicAuth("frank", "correct-horse-battery")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	server.SetSessionConfig(SessionConfig{
		IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, Secure: true,
		AllowBasicAuth: true, PublicURL: "https://raiwall.example.com",
	})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.SetBasicAuth("frank", "correct-horse-battery")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestUnknownUserAndWrongPasswordTakeSamePath(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	createOperator(t, store, "grace", "correct-horse-battery", RoleAdmin)

	for _, attempt := range []struct{ username, password string }{
		{"grace", "wrong"},
		{"nobody", "wrong"},
	} {
		body, _ := json.Marshal(map[string]string{"username": attempt.username, "password": attempt.password})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Equal(t, `{"error":"invalid username or password"}`+"\n", rec.Body.String())
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	secureSessionServer(t, server)
	createOperator(t, store, "heidi", "correct-horse-battery", RoleAdmin)
	cookie := login(t, server, "heidi", "correct-horse-battery")

	session, err := store.GetAdminSessionByTokenHash(context.Background(), server.AuthManager().hashToken(cookie.Value))
	require.NoError(t, err)
	expired := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, store.TouchAdminSession(context.Background(), session.ID, expired, expired))

	me := authedRequest(server, http.MethodGet, "/api/v1/auth/me", cookie, "")
	require.Equal(t, http.StatusUnauthorized, me.Code, "an idle-expired session must not authenticate")
}
