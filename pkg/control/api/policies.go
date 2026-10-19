package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type RatePolicyDTO struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Host                string    `json:"host"`
	Tier1Rate           int64     `json:"tier1_rate"`
	Tier1Burst          int64     `json:"tier1_burst"`
	Tier1PeriodSec      int64     `json:"tier1_period_sec"`
	Tier2Threshold      int64     `json:"tier2_threshold"`
	Tier2PeriodSec      int64     `json:"tier2_period_sec"`
	Tier2BanDurationSec int64     `json:"tier2_ban_duration_sec"`
	Tier3Threshold      int64     `json:"tier3_threshold"`
	Tier3BanDurationSec int64     `json:"tier3_ban_duration_sec"`
	WaitingRoomEnabled  bool      `json:"waiting_room_enabled"`
	WaitingRoomCapacity int64     `json:"waiting_room_capacity"`
	IsActive            bool      `json:"is_active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type BotConfigDTO struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	PowEnabled    bool      `json:"pow_enabled"`
	PowDifficulty int       `json:"pow_difficulty"`
	TrapURLs      []string  `json:"trap_urls"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Rate policies
func (s *Server) handleListRatePolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListRatePolicies(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list rate policies: "+err.Error())
		return
	}

	result := make([]RatePolicyDTO, 0, len(policies))
	for _, p := range policies {
		result = append(result, RatePolicyDTO{
			ID:                  p.ID,
			Name:                p.Name,
			Host:                p.Host,
			Tier1Rate:           p.Tier1Rate,
			Tier1Burst:          p.Tier1Burst,
			Tier1PeriodSec:      p.Tier1PeriodSec,
			Tier2Threshold:      p.Tier2Threshold,
			Tier2PeriodSec:      p.Tier2PeriodSec,
			Tier2BanDurationSec: p.Tier2BanDurationSec,
			Tier3Threshold:      p.Tier3Threshold,
			Tier3BanDurationSec: p.Tier3BanDurationSec,
			WaitingRoomEnabled:  p.WaitingRoomEnabled == 1,
			WaitingRoomCapacity: p.WaitingRoomCapacity,
			IsActive:            p.IsActive == 1,
			CreatedAt:           p.CreatedAt,
			UpdatedAt:           p.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetRatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := s.store.GetRatePolicy(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "rate policy not found")
		return
	}

	respondJSON(w, http.StatusOK, RatePolicyDTO{
		ID:                  p.ID,
		Name:                p.Name,
		Host:                p.Host,
		Tier1Rate:           p.Tier1Rate,
		Tier1Burst:          p.Tier1Burst,
		Tier1PeriodSec:      p.Tier1PeriodSec,
		Tier2Threshold:      p.Tier2Threshold,
		Tier2PeriodSec:      p.Tier2PeriodSec,
		Tier2BanDurationSec: p.Tier2BanDurationSec,
		Tier3Threshold:      p.Tier3Threshold,
		Tier3BanDurationSec: p.Tier3BanDurationSec,
		WaitingRoomEnabled:  p.WaitingRoomEnabled == 1,
		WaitingRoomCapacity: p.WaitingRoomCapacity,
		IsActive:            p.IsActive == 1,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	})
}

func (s *Server) handleCreateRatePolicy(w http.ResponseWriter, r *http.Request) {
	var req RatePolicyDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ID == "" {
		req.ID = "rate-" + uuid.New().String()[:8]
	}
	if req.Tier1PeriodSec == 0 {
		req.Tier1PeriodSec = 60
	}
	if req.Tier2PeriodSec == 0 {
		req.Tier2PeriodSec = 60
	}
	if req.Tier2BanDurationSec == 0 {
		req.Tier2BanDurationSec = 3600
	}
	if req.Tier3BanDurationSec == 0 {
		req.Tier3BanDurationSec = 86400
	}

	now := time.Now().UTC()
	var wrEnabled, isActive int64
	if req.WaitingRoomEnabled {
		wrEnabled = 1
	}
	if req.IsActive {
		isActive = 1
	}

	err := s.store.CreateRatePolicy(r.Context(), db.CreateRatePolicyParams{
		ID:                  req.ID,
		Name:                req.Name,
		Host:                req.Host,
		Tier1Rate:           req.Tier1Rate,
		Tier1Burst:          req.Tier1Burst,
		Tier1PeriodSec:      req.Tier1PeriodSec,
		Tier2Threshold:      req.Tier2Threshold,
		Tier2PeriodSec:      req.Tier2PeriodSec,
		Tier2BanDurationSec: req.Tier2BanDurationSec,
		Tier3Threshold:      req.Tier3Threshold,
		Tier3BanDurationSec: req.Tier3BanDurationSec,
		WaitingRoomEnabled:  wrEnabled,
		WaitingRoomCapacity: req.WaitingRoomCapacity,
		IsActive:            isActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create rate policy: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateRatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req RatePolicyDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	now := time.Now().UTC()
	var wrEnabled, isActive int64
	if req.WaitingRoomEnabled {
		wrEnabled = 1
	}
	if req.IsActive {
		isActive = 1
	}

	err := s.store.UpdateRatePolicy(r.Context(), db.UpdateRatePolicyParams{
		ID:                  id,
		Name:                req.Name,
		Host:                req.Host,
		Tier1Rate:           req.Tier1Rate,
		Tier1Burst:          req.Tier1Burst,
		Tier1PeriodSec:      req.Tier1PeriodSec,
		Tier2Threshold:      req.Tier2Threshold,
		Tier2PeriodSec:      req.Tier2PeriodSec,
		Tier2BanDurationSec: req.Tier2BanDurationSec,
		Tier3Threshold:      req.Tier3Threshold,
		Tier3BanDurationSec: req.Tier3BanDurationSec,
		WaitingRoomEnabled:  wrEnabled,
		WaitingRoomCapacity: req.WaitingRoomCapacity,
		IsActive:            isActive,
		UpdatedAt:           now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update rate policy: "+err.Error())
		return
	}

	req.ID = id
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteRatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteRatePolicy(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete rate policy: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// Bot configs
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
		req.PowDifficulty = 4
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

	err := s.store.CreateBotConfig(r.Context(), db.CreateBotConfigParams{
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

	err := s.store.UpdateBotConfig(r.Context(), db.UpdateBotConfigParams{
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
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
