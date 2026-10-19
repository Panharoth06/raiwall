package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/pkg/control/db"
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

// AuthMiddleware verifies API tokens or session cookies and enforces 2-tier RBAC.
func (am *AuthManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Public endpoints that bypass authentication
		if path == "/api/v1/auth/login" ||
			path == "/.raiwall/api/openapi.json" ||
			path == "/.raiwall/api/docs" ||
			path == "/.raiwall/api/swagger" {
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
						_ = am.store.UpdateAPIKeyLastUsed(context.Background(), db.UpdateAPIKeyLastUsedParams{
							ID:         kID,
							LastUsedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
						})
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
		if path == "/api/v1/auth/logout" {
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
