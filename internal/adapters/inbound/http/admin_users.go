package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	minOperatorPasswordLength = 12
	minOperatorUsernameLength = 3
	maxOperatorUsernameLength = 64
)

// AdminUserDTO is the operator account representation returned by the API.
// Password hashes are never exposed.
type AdminUserDTO struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type createAdminUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type updateAdminUserRequest struct {
	Role     *string `json:"role"`
	IsActive *bool   `json:"is_active"`
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

type adminUserResponse struct {
	User     AdminUserDTO `json:"user"`
	Password string       `json:"password,omitempty"`
}

func toAdminUserDTO(user control.UserRecord) AdminUserDTO {
	return AdminUserDTO{
		ID:        user.ID,
		Username:  user.Username,
		Role:      user.Role,
		IsActive:  user.IsActive == 1,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// requireOperatorAdmin rejects non-admin principals, including for read-only
// operator listings.
func requireOperatorAdmin(w http.ResponseWriter, r *http.Request) (*AuthContext, bool) {
	authCtx, ok := AuthFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return nil, false
	}
	if authCtx.Role != RoleAdmin {
		respondError(w, http.StatusForbidden, "Forbidden: operator management requires admin role")
		return nil, false
	}
	return authCtx, true
}

func validateOperatorUsername(username string) error {
	trimmed := strings.TrimSpace(username)
	if len(trimmed) < minOperatorUsernameLength || len(trimmed) > maxOperatorUsernameLength {
		return errString("username must be between 3 and 64 characters")
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '@':
		default:
			return errString("username may only contain letters, digits, '.', '_', '-', or '@'")
		}
	}
	return nil
}

func validateOperatorRole(role string) error {
	switch role {
	case RoleAdmin, RoleViewer:
		return nil
	default:
		return errString("role must be admin or viewer")
	}
}

func validateOperatorPassword(password string) error {
	if len(password) < minOperatorPasswordLength {
		return errString("password must be at least 12 characters")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func generateOperatorPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) handleListAdminUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list operators: "+err.Error())
		return
	}
	result := make([]AdminUserDTO, 0, len(users))
	for _, user := range users {
		result = append(result, toAdminUserDTO(user))
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateAdminUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	var req createAdminUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if err := validateOperatorUsername(req.Username); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = RoleViewer
	}
	if err := validateOperatorRole(req.Role); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	generated := false
	if req.Password == "" {
		password, err := generateOperatorPassword()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to generate password")
			return
		}
		req.Password = password
		generated = true
	}
	if err := validateOperatorPassword(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := s.store.GetUserByUsername(r.Context(), req.Username); err == nil {
		respondError(w, http.StatusConflict, "username already exists")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	now := time.Now().UTC()
	user := control.UserRecord{
		ID:           uuid.NewString(),
		Username:     req.Username,
		PasswordHash: hash,
		Role:         req.Role,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		respondError(w, http.StatusConflict, "failed to create operator: "+err.Error())
		return
	}

	resp := adminUserResponse{User: toAdminUserDTO(user)}
	if generated {
		resp.Password = req.Password
	}
	respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleUpdateAdminUser(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := requireOperatorAdmin(w, r)
	if !ok {
		return
	}
	var req updateAdminUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role == nil && req.IsActive == nil {
		respondError(w, http.StatusBadRequest, "specify role and/or is_active")
		return
	}
	if req.Role != nil {
		if err := validateOperatorRole(*req.Role); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Serialize the last-admin check with the write it authorizes; otherwise two
	// concurrent demotions can each observe the other admin and both proceed.
	s.operatorMu.Lock()
	defer s.operatorMu.Unlock()

	target, err := s.store.GetUserByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "operator not found")
		return
	}

	newRole := target.Role
	if req.Role != nil {
		newRole = *req.Role
	}
	newActive := target.IsActive == 1
	if req.IsActive != nil {
		newActive = *req.IsActive
	}

	if target.ID == authCtx.UserID && (newRole != RoleAdmin || !newActive) {
		respondError(w, http.StatusConflict, "you cannot demote or deactivate your own account")
		return
	}
	if removed, err := s.wouldRemoveLastAdmin(r.Context(), target, newRole, newActive); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to check operator roles")
		return
	} else if removed {
		respondError(w, http.StatusConflict, "at least one active admin is required")
		return
	}

	target.Role = newRole
	if newActive {
		target.IsActive = 1
	} else {
		target.IsActive = 0
	}
	target.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), target); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update operator: "+err.Error())
		return
	}
	// Role and state changes invalidate every existing session immediately.
	_ = s.authMgr.RevokeUserSessions(r.Context(), target.ID)

	respondJSON(w, http.StatusOK, adminUserResponse{User: toAdminUserDTO(target)})
}

func (s *Server) handleResetAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	var req resetPasswordRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	generated := false
	if req.Password == "" {
		password, err := generateOperatorPassword()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to generate password")
			return
		}
		req.Password = password
		generated = true
	}
	if err := validateOperatorPassword(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := s.store.GetUserByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "operator not found")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	target.PasswordHash = hash
	target.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), target); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to reset password: "+err.Error())
		return
	}
	_ = s.authMgr.RevokeUserSessions(r.Context(), target.ID)

	resp := adminUserResponse{User: toAdminUserDTO(target)}
	if generated {
		resp.Password = req.Password
	}
	respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRevokeAdminUserSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	target, err := s.store.GetUserByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "operator not found")
		return
	}
	if err := s.authMgr.RevokeUserSessions(r.Context(), target.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to revoke sessions")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "sessions_revoked"})
}

func (s *Server) handleDeactivateAdminUser(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := requireOperatorAdmin(w, r)
	if !ok {
		return
	}
	s.operatorMu.Lock()
	defer s.operatorMu.Unlock()

	target, err := s.store.GetUserByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "operator not found")
		return
	}
	if target.ID == authCtx.UserID {
		respondError(w, http.StatusConflict, "you cannot deactivate your own account")
		return
	}
	if removed, err := s.wouldRemoveLastAdmin(r.Context(), target, target.Role, false); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to check operator roles")
		return
	} else if removed {
		respondError(w, http.StatusConflict, "at least one active admin is required")
		return
	}

	target.IsActive = 0
	target.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateUser(r.Context(), target); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to deactivate operator: "+err.Error())
		return
	}
	_ = s.authMgr.RevokeUserSessions(r.Context(), target.ID)
	respondJSON(w, http.StatusOK, adminUserResponse{User: toAdminUserDTO(target)})
}

// wouldRemoveLastAdmin reports whether applying role/active would leave no
// active admin accounts.
func (s *Server) wouldRemoveLastAdmin(ctx context.Context, target control.UserRecord, newRole string, newActive bool) (bool, error) {
	if target.Role != RoleAdmin || target.IsActive != 1 {
		return false, nil
	}
	if newRole == RoleAdmin && newActive {
		return false, nil
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	for _, user := range users {
		if user.ID == target.ID || user.Role != RoleAdmin || user.IsActive != 1 {
			continue
		}
		return false, nil
	}
	return true, nil
}
