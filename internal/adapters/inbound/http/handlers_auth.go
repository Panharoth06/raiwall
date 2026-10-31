package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
)

// LoginRequest represents incoming login credentials.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !s.authMgr.OriginAllowed(r) {
		respondError(w, http.StatusForbidden, "cross-origin login rejected")
		return
	}

	clientIP := clientIPFromRequest(r)
	user, err := s.authMgr.CheckCredentials(r.Context(), req.Username, req.Password, clientIP)

	var locked *LoginLockedError
	if errors.As(err, &locked) {
		retry := int(math.Ceil(locked.RetryAfter.Seconds()))
		if retry < 1 {
			retry = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		respondError(w, http.StatusTooManyRequests, "too many failed login attempts")
		return
	}
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	cookie, err := s.authMgr.CreateSessionCookie(r.Context(), &user, clientIP, r.UserAgent())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	http.SetCookie(w, cookie)
	respondJSON(w, http.StatusOK, map[string]any{
		"message":  "login successful",
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if authCtx, ok := AuthFromContext(r.Context()); ok && authCtx.SessionID != "" {
		_ = s.authMgr.RevokeSession(r.Context(), authCtx.SessionID)
	}
	http.SetCookie(w, s.authMgr.ClearSessionCookie())
	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := AuthFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	respondJSON(w, http.StatusOK, authCtx)
}
