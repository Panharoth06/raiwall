package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type APIKeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsActive   bool       `json:"is_active"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	APIKeyDTO
	RawKey string `json:"raw_key"`
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list api keys: "+err.Error())
		return
	}

	result := make([]APIKeyDTO, 0, len(keys))
	for _, k := range keys {
		var exp, last *time.Time
		if k.ExpiresAt.Valid {
			exp = &k.ExpiresAt.Time
		}
		if k.LastUsedAt.Valid {
			last = &k.LastUsedAt.Time
		}
		result = append(result, APIKeyDTO{
			ID:         k.ID,
			Name:       k.Name,
			Role:       k.Role,
			ExpiresAt:  exp,
			IsActive:   k.IsActive == 1,
			CreatedAt:  k.CreatedAt,
			LastUsedAt: last,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Role == "" {
		req.Role = RoleViewer
	}
	if req.Name == "" {
		req.Name = "API Key"
	}

	// Generate 32 bytes random key token
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	rawKey := "rw_" + hex.EncodeToString(tokenBytes)
	keyHash := HashAPIKey(rawKey)

	id := "key-" + uuid.New().String()[:8]
	now := time.Now().UTC()

	var expNull sql.NullTime
	if req.ExpiresAt != nil {
		expNull = sql.NullTime{Time: *req.ExpiresAt, Valid: true}
	}

	err := s.store.CreateAPIKey(r.Context(), db.CreateAPIKeyParams{
		ID:        id,
		Name:      req.Name,
		KeyHash:   keyHash,
		Role:      req.Role,
		ExpiresAt: expNull,
		IsActive:  1,
		CreatedAt: now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create api key: "+err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, CreateAPIKeyResponse{
		APIKeyDTO: APIKeyDTO{
			ID:        id,
			Name:      req.Name,
			Role:      req.Role,
			ExpiresAt: req.ExpiresAt,
			IsActive:  true,
			CreatedAt: now,
		},
		RawKey: rawKey,
	})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteAPIKey(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to revoke api key: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
