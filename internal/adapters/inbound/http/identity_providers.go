package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Identity provider (external IdP connector) REST surface.

// IdentityProviderDTO is the JSON view of a stored connector. The raw config
// blob is echoed back so the UI can round-trip editing.
type IdentityProviderDTO struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	Managed   bool            `json:"managed"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// identityProviderCreate is the POST /identity/providers payload.
type identityProviderCreate struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled"`
}

var identityProviderTypes = map[string]bool{
	auth.ProviderTypeSimple: true,
	auth.ProviderTypeOIDC:   true,
	auth.ProviderTypeLDAP:   true,
	auth.ProviderTypeGitHub: true,
}

func providerRecordToDTO(p control.IdentityProviderRecord) IdentityProviderDTO {
	return IdentityProviderDTO{
		ID:        p.ID,
		Type:      p.Type,
		Name:      p.Name,
		Config:    json.RawMessage(strings.TrimSpace(p.Config)),
		Enabled:   p.Enabled == 1,
		Managed:   declarative.IsManaged(p.ID),
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// convertProvider compiles the stored spec into a live connector; a non-nil
// error marks the stored config as broken.
func (s *Server) convertProvider(r *http.Request, p control.IdentityProviderRecord) error {
	var simple *auth.SimpleAuth
	if p.Type == auth.ProviderTypeSimple {
		simple = s.simpleAuthAdapter(r)
	}
	_, err := auth.NewIdentityProvider(auth.IdentityProviderSpec{
		Type: p.Type, Name: p.Name, ConfigJSON: p.Config,
	}, simple)
	return err
}

func (s *Server) handleListIdentityProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListIdentityProviders(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list identity providers: "+err.Error())
		return
	}
	result := make([]IdentityProviderDTO, 0, len(providers))
	for _, p := range providers {
		result = append(result, providerRecordToDTO(p))
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	var req identityProviderCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Type = strings.TrimSpace(req.Type)
	req.Name = strings.TrimSpace(req.Name)
	if req.Type == "" || req.Name == "" {
		respondError(w, http.StatusBadRequest, "type and name are required")
		return
	}
	if !identityProviderTypes[req.Type] {
		respondError(w, http.StatusBadRequest, "unsupported provider type: "+req.Type)
		return
	}
	// Config must parse as a valid JSON object.
	_, err := json.RawMessage(req.Config).MarshalJSON()
	if err != nil {
		respondError(w, http.StatusBadRequest, "config must be a JSON object: "+err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Fail fast: the archived spec must compile into a live connector.
	if _, err := auth.NewIdentityProvider(auth.IdentityProviderSpec{
		Type: req.Type, Name: req.Name, ConfigJSON: string(req.Config),
	}, s.simpleAuthAdapter(r)); err != nil {
		respondError(w, http.StatusBadRequest, "provider config rejected: "+err.Error())
		return
	}

	now := time.Now().UTC()
	record := control.IdentityProviderRecord{
		ID:        "idp-" + uuid.New().String()[:8],
		Type:      req.Type,
		Name:      req.Name,
		Config:    string(req.Config),
		Enabled:   boolToInt64(enabled),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.UpsertIdentityProvider(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create identity provider: "+err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, providerRecordToDTO(record))
}

// identityProviderUpdate is the PUT /identity/providers/{id} payload.
type identityProviderUpdate struct {
	Name    *string         `json:"name"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled"`
}

func (s *Server) handleUpdateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.store.ListIdentityProviders(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load identity providers: "+err.Error())
		return
	}
	var found *control.IdentityProviderRecord
	for i := range record {
		if record[i].ID == id {
			found = &record[i]
			break
		}
	}
	if found == nil {
		respondError(w, http.StatusNotFound, "identity provider not found")
		return
	}

	var req identityProviderUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			respondError(w, http.StatusBadRequest, "name cannot be empty")
			return
		}
		found.Name = strings.TrimSpace(*req.Name)
	}
	if req.Config != nil {
		if _, err := json.RawMessage(req.Config).MarshalJSON(); err != nil {
			respondError(w, http.StatusBadRequest, "config must be a JSON object: "+err.Error())
			return
		}
		found.Config = string(req.Config)
	}
	if req.Enabled != nil {
		found.Enabled = boolToInt64(*req.Enabled)
	}
	found.UpdatedAt = time.Now().UTC()

	if _, err := auth.NewIdentityProvider(auth.IdentityProviderSpec{
		Type: found.Type, Name: found.Name, ConfigJSON: found.Config,
	}, s.simpleAuthAdapter(r)); err != nil {
		respondError(w, http.StatusBadRequest, "provider config rejected: "+err.Error())
		return
	}

	if err := s.store.UpsertIdentityProvider(r.Context(), *found); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update identity provider: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, providerRecordToDTO(*found))
}

func (s *Server) handleDeleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	providers, err := s.store.ListIdentityProviders(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load identity providers: "+err.Error())
		return
	}
	for _, p := range providers {
		if p.ID == id {
			if err := s.store.DeleteIdentityProvider(r.Context(), id); err != nil {
				respondError(w, http.StatusInternalServerError, "failed to delete identity provider: "+err.Error())
				return
			}
			respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
			return
		}
	}
	respondError(w, http.StatusNotFound, "identity provider not found")
}

// simpleAuthAdapter returns the local directory adapter backing the "simple"
// provider type for config compile checks.
func (s *Server) simpleAuthAdapter(_ *http.Request) *auth.SimpleAuth {
	// The end-user local directory is managed through the SQL store; use an
	// empty in-memory adapter purely for spec compile validation.
	return auth.NewSimpleAuth()
}
