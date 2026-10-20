package api

import (
	"encoding/json"
	"net/http"
	"time"
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

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user.IsActive != 1 {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if !CheckPassword(req.Password, user.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	cookie, err := s.authMgr.GenerateSessionCookie(&user, 24*time.Hour)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create session: "+err.Error())
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
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
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
