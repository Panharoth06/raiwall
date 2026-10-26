package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/go-chi/chi/v5"
)

type contextKey string

const authContextKey contextKey = "raiwall_auth_context"

// ContextWithAuth stores AuthContext in request context.
func ContextWithAuth(ctx context.Context, ac *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, ac)
}

// AuthFromContext extracts AuthContext from request context.
func AuthFromContext(ctx context.Context) (*AuthContext, bool) {
	ac, ok := ctx.Value(authContextKey).(*AuthContext)
	return ac, ok && ac != nil
}

// DeclarativeGuardMiddleware rejects mutations of records owned by
// raiwall.yaml. Operators change the file and redeploy instead of drifting the
// database away from Git.
func DeclarativeGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		for _, param := range []string{"id", "rule_id", "entryId"} {
			if declarative.IsManaged(chi.URLParam(r, param)) {
				respondError(w, http.StatusConflict,
					"resource is managed by the declarative configuration file; edit raiwall.yaml and redeploy")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware verifies API tokens or session cookies and enforces 2-tier RBAC.
func (am *AuthManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Public endpoints that bypass authentication
		if path == "/api/v1/auth/login" ||
			path == "/.raiwall/api/v1/auth/login" ||
			path == "/.raiwall/api/openapi.json" ||
			path == "/.raiwall/api/docs" ||
			path == "/.raiwall/api/swagger" ||
			path == "/api/openapi.json" ||
			path == "/api/docs" ||
			path == "/api/swagger" {
			next.ServeHTTP(w, r)
			return
		}

		var authCtx *AuthContext
		var authErr error

		// 1. Try Bearer Token or X-Raiwall-Key
		token := r.Header.Get("X-Raiwall-Key")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		// Query param support for EventSource / SSE clients
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			token = r.URL.Query().Get("api_key")
		}
		if token == "" {
			token = r.URL.Query().Get("key")
		}

		if token != "" {
			keyHash := HashAPIKey(token)
			keyRecord, err := am.store.GetAPIKeyByHash(r.Context(), keyHash)
			if err == nil && keyRecord.IsActive == 1 {
				// Check expiration
				if !keyRecord.ExpiresAt.Valid || keyRecord.ExpiresAt.Time.After(time.Now().UTC()) {
					authCtx = &AuthContext{
						Role:     keyRecord.Role,
						IsAPIKey: true,
						KeyID:    keyRecord.ID,
						Username: keyRecord.Name,
					}
					// Asynchronously record last used
					go func(kID string) {
						_ = am.store.UpdateAPIKeyLastUsed(context.Background(), kID, time.Now().UTC())
					}(keyRecord.ID)
				}
			}
		}

		// 2. Try Session Cookie if no API key
		if authCtx == nil {
			cookie, err := r.Cookie(SessionCookieName)
			if err == nil {
				authCtx, authErr = am.VerifySessionCookie(cookie)
			}
		}

		// 3. Try HTTP Basic Auth
		if authCtx == nil {
			if user, pass, ok := r.BasicAuth(); ok {
				u, err := am.store.GetUserByUsername(r.Context(), user)
				if err == nil && u.IsActive == 1 && CheckPassword(pass, u.PasswordHash) {
					authCtx = &AuthContext{
						UserID:   u.ID,
						Username: u.Username,
						Role:     u.Role,
					}
				}
			}
		}

		// If still unauthenticated, return 401
		if authCtx == nil {
			reason := "unauthorized: valid API key or session cookie required"
			if authErr != nil {
				reason = authErr.Error()
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": reason,
			})
			return
		}

		// 3. Enforce 2-Tier RBAC on mutating methods
		isMutating := r.Method == http.MethodPost ||
			r.Method == http.MethodPut ||
			r.Method == http.MethodDelete ||
			r.Method == http.MethodPatch

		// Allow logout for all authenticated users
		if strings.HasSuffix(path, "/auth/logout") {
			isMutating = false
		}
		// Allow test / dry-run simulation endpoints for viewers
		if strings.HasSuffix(path, "/test") || strings.HasSuffix(path, "/dry-run") {
			isMutating = false
		}
		// Allow MCP message JSON-RPC handler (tool-level RBAC is checked inside executor)
		if strings.HasSuffix(path, "/mcp/message") {
			isMutating = false
		}

		if isMutating && authCtx.Role != RoleAdmin {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Forbidden: write operations require admin role",
			})
			return
		}

		// Put AuthContext into context
		ctx := ContextWithAuth(r.Context(), authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
