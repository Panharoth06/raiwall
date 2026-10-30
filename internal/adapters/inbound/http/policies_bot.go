package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// BotConfigDTO represents bot defense parameters and trap endpoints.
type BotConfigDTO struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	PowEnabled    bool      `json:"pow_enabled"`
	PowDifficulty int       `json:"pow_difficulty"`
	TrapURLs      []string  `json:"trap_urls"`
	IsActive      bool      `json:"is_active"`
	Managed       bool      `json:"managed"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *Server) handleListBotConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.store.ListBotConfigs(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list bot configs: "+err.Error())
		return
	}

	result := make([]BotConfigDTO, 0, len(configs))
	for _, b := range configs {
		var traps []string
		_ = json.Unmarshal([]byte(b.TrapUrls), &traps)
		result = append(result, BotConfigDTO{
			ID:            b.ID,
			Managed:       declarative.IsManaged(b.ID),
			Host:          b.Host,
			PowEnabled:    b.PowEnabled == 1,
			PowDifficulty: int(b.PowDifficulty),
			TrapURLs:      traps,
			IsActive:      b.IsActive == 1,
			CreatedAt:     b.CreatedAt,
			UpdatedAt:     b.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetBotConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	b, err := s.store.GetBotConfig(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "bot config not found")
		return
	}

	var traps []string
	_ = json.Unmarshal([]byte(b.TrapUrls), &traps)
	respondJSON(w, http.StatusOK, BotConfigDTO{
		ID:            b.ID,
		Managed:       declarative.IsManaged(b.ID),
		Host:          b.Host,
		PowEnabled:    b.PowEnabled == 1,
		PowDifficulty: int(b.PowDifficulty),
		TrapURLs:      traps,
		IsActive:      b.IsActive == 1,
		CreatedAt:     b.CreatedAt,
		UpdatedAt:     b.UpdatedAt,
	})
}

func (s *Server) handleCreateBotConfig(w http.ResponseWriter, r *http.Request) {
	var req BotConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ID == "" {
		req.ID = "bot-" + uuid.New().String()[:8]
	}
	if req.PowDifficulty == 0 {
		req.PowDifficulty = 20000
	}

	trapsJSON, _ := json.Marshal(req.TrapURLs)
	now := time.Now().UTC()
	var powEnabled, isActive int64
	if req.PowEnabled {
		powEnabled = 1
	}
	if req.IsActive {
		isActive = 1
	}

	err := s.store.CreateBotConfig(r.Context(), control.BotConfig{
		ID:            req.ID,
		Host:          req.Host,
		PowEnabled:    powEnabled,
		PowDifficulty: int64(req.PowDifficulty),
		TrapUrls:      string(trapsJSON),
		IsActive:      isActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create bot config: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateBotConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req BotConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	trapsJSON, _ := json.Marshal(req.TrapURLs)
	now := time.Now().UTC()
	var powEnabled, isActive int64
	if req.PowEnabled {
		powEnabled = 1
	}
	if req.IsActive {
		isActive = 1
	}

	err := s.store.UpdateBotConfig(r.Context(), control.BotConfig{
		ID:            id,
		Host:          req.Host,
		PowEnabled:    powEnabled,
		PowDifficulty: int64(req.PowDifficulty),
		TrapUrls:      string(trapsJSON),
		IsActive:      isActive,
		UpdatedAt:     now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update bot config: "+err.Error())
		return
	}
	_ = declarative.Override(r.Context(), s.store, id)

	req.ID = id
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteBotConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteBotConfig(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete bot config: "+err.Error())
		return
	}
	_ = declarative.Override(r.Context(), s.store, id)
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
