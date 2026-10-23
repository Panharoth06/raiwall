package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"database/sql"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Identity user directory REST surface (end-user accounts, separate from admin operators).

// IdentityUserDTO is the JSON view of a directory account. Secrets are never exposed.
type IdentityUserDTO struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	TOTPEnrolled bool      `json:"totp_enrolled"`
	AppIDs       []string  `json:"app_ids"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IdentityUserEnrollment is returned on create / TOTP reset; carries the
// plaintext 2FA secret exactly once at enrollment time.
type IdentityUserEnrollment struct {
	IdentityUserDTO
	TOTPSecret       string `json:"totp_secret,omitempty"`
	TOTPProvisionURI string `json:"totp_provisioning_uri,omitempty"`
}

func parseAppIDs(raw string) []string {
	var ids []string
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &ids)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

func identityUserRecordToDTO(u control.IdentityUserRecord) IdentityUserDTO {
	return IdentityUserDTO{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		TOTPEnrolled: u.TOTPEnabled == 1,
		AppIDs:       parseAppIDs(u.AppIDs),
		Enabled:      u.Enabled == 1,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

func (s *Server) handleListIdentityUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListIdentityUsers(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list identity users: "+err.Error())
		return
	}

	result := make([]IdentityUserDTO, 0, len(users))
	for _, u := range users {
		result = append(result, identityUserRecordToDTO(u))
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetIdentityUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := s.store.GetIdentityUserByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "identity user not found")
		return
	}
	respondJSON(w, http.StatusOK, identityUserRecordToDTO(u))
}

// identityUserCreate is the POST /identity/users payload.
type identityUserCreate struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	AppIDs      []string `json:"app_ids"`
	// nil = default true so accounts are usable immediately.
	Enabled *bool `json:"enabled"`
}

const identityUsersMaxAccounts = 5000

func (s *Server) handleCreateIdentityUser(w http.ResponseWriter, r *http.Request) {
	var req identityUserCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 8 {
		respondError(w, http.StatusBadRequest, "username required; password must be at least 8 characters")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Unique username check (defensive: the DB enforces it too).
	if _, err := s.store.GetIdentityUserByUsername(r.Context(), req.Username); err == nil {
		respondError(w, http.StatusConflict, "username already exists")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		respondError(w, http.StatusInternalServerError, "username lookup failed: "+err.Error())
		return
	}
	// Explicit directory size cap (enterprise tier packaging).
	if existing, err := s.store.ListIdentityUsers(r.Context()); err == nil && len(existing) >= identityUsersMaxAccounts {
		respondError(w, http.StatusForbidden, "identity directory full: max "+strconv.Itoa(identityUsersMaxAccounts)+" accounts")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password: "+err.Error())
		return
	}

	appIDs, _ := json.Marshal(req.AppIDs)
	now := time.Now().UTC()
	record := control.IdentityUserRecord{
		ID:           "idusr-" + uuid.New().String()[:8],
		Username:     req.Username,
		PasswordHash: hash,
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  req.DisplayName,
		TOTPEnabled:  0,
		AppIDs:       string(appIDs),
		Enabled:      boolToInt64(enabled),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.store.UpsertIdentityUser(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create identity user: "+err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, IdentityUserEnrollment{
		IdentityUserDTO: identityUserRecordToDTO(record),
	})
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// identityUserUpdate is the PUT /identity/users/{id} payload. The password
// rotates only through the dedicated password-reset endpoint.
type identityUserUpdate struct {
	Email       *string  `json:"email"`
	DisplayName *string  `json:"display_name"`
	AppIDs      []string `json:"app_ids"`
	Enabled     *bool    `json:"enabled"`
}

func (s *Server) handleUpdateIdentityUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.store.GetIdentityUserByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "identity user not found")
		return
	}

	var req identityUserUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email != nil {
		record.Email = strings.TrimSpace(*req.Email)
	}
	if req.DisplayName != nil {
		record.DisplayName = *req.DisplayName
	}
	if req.AppIDs != nil {
		appIDs, _ := json.Marshal(req.AppIDs)
		record.AppIDs = string(appIDs)
	}
	if req.Enabled != nil {
		record.Enabled = boolToInt64(*req.Enabled)
	}
	record.UpdatedAt = time.Now().UTC()

	if err := s.store.UpsertIdentityUser(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update identity user: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, identityUserRecordToDTO(record))
}

func (s *Server) handleDeleteIdentityUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.GetIdentityUserByID(r.Context(), id); err != nil {
		respondError(w, http.StatusNotFound, "identity user not found")
		return
	}
	if err := s.store.DeleteIdentityUser(r.Context(), id); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete identity user: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// passwordReset is the POST /identity/users/{id}/password-reset payload.
type passwordReset struct {
	NewPassword string `json:"new_password"`
}

func (s *Server) handleResetIdentityUserPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.store.GetIdentityUserByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "identity user not found")
		return
	}

	var req passwordReset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 8 {
		respondError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to hash password: "+err.Error())
		return
	}
	record.PasswordHash = hash
	record.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertIdentityUser(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to reset password: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, identityUserRecordToDTO(record))
}

// totpReset is the POST /identity/users/{id}/totp-reset payload.
type totpReset struct {
	// Enroll toggles 2FA on and issues a fresh secret; false disables the factor.
	Enroll bool `json:"enroll"`
}

func (s *Server) handleResetIdentityUserTOTP(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.store.GetIdentityUserByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "identity user not found")
		return
	}

	var req totpReset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var newSecret string
	if !req.Enroll {
		record.TOTPSecret = ""
		record.TOTPEnabled = 0
	} else {
		// Each rotation invalidates prior authenticator entries.
		secret, _, genErr := auth.GenerateTOTPSecret(auth.TOTPIssuer, record.Username)
		if genErr != nil {
			respondError(w, http.StatusInternalServerError, "failed to generate totp secret: "+genErr.Error())
			return
		}
		record.TOTPSecret = secret
		record.TOTPEnabled = 1
		newSecret = secret
	}
	record.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertIdentityUser(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update totp state: "+err.Error())
		return
	}

	response := IdentityUserEnrollment{
		IdentityUserDTO:  identityUserRecordToDTO(record),
		TOTPSecret:       newSecret,
		TOTPProvisionURI: "",
	}
	if newSecret != "" {
		response.TOTPProvisionURI = auth.TOTPProvisionURI(auth.TOTPIssuer, record.Username, newSecret)
	}
	respondJSON(w, http.StatusOK, response)
}
