package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

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

// DeclarativeGuardMiddleware intercepts mutations on declarative resources and
// records an ownership override so declarative sync skips them on redeploy.
func (s *Server) DeclarativeGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		for _, param := range []string{"id", "rule_id", "entryId"} {
			paramVal := chi.URLParam(r, param)
			if declarative.IsManaged(paramVal) {
				_ = declarative.Override(r.Context(), s.store, paramVal)
			}
		}
		if codeStr := chi.URLParam(r, "statusCode"); codeStr != "" {
			if code, err := strconv.Atoi(codeStr); err == nil {
				_ = declarative.Override(r.Context(), s.store, declarative.TemplateID(code))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// DeclarativeGuardMiddleware is a backwards-compatible package-level middleware.
func DeclarativeGuardMiddleware(next http.Handler) http.Handler {
	return next
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

		authCtx, authErr := am.Authenticate(r)

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

		// Cookie-authenticated mutations must come from this origin. API-key and
		// Basic clients are exempt because they carry explicit credentials.
		if isMutating && authCtx.Method == "cookie" && !am.OriginAllowed(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Forbidden: cross-origin request rejected",
			})
			return
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
