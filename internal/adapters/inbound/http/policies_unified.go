package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

// UnifiedPolicyDTO combines rate limiting and bot defense configurations into a single payload.
type UnifiedPolicyDTO struct {
	Tier1Rate                int64    `json:"tier1_rate"`
	Tier1Burst               int64    `json:"tier1_burst"`
	Tier2Threshold           int64    `json:"tier2_threshold"`
	Tier2BanSeconds          int64    `json:"tier2_ban_seconds"`
	Tier3Threshold           int64    `json:"tier3_threshold"`
	Tier3BanSeconds          int64    `json:"tier3_ban_seconds"`
	BotDefenseMode           string   `json:"bot_defense_mode"`
	PowDifficulty            int      `json:"pow_difficulty"`
	HoneypotEnabled          bool     `json:"honeypot_enabled"`
	WaitingRoomEnabled       bool     `json:"waiting_room_enabled"`
	WaitingRoomMaxConcurrent int64    `json:"waiting_room_max_concurrent"`
	WaitingRoomPaths         []string `json:"waiting_room_paths,omitempty"`
}

func (s *Server) handleGetUnifiedPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ratePolicies, _ := s.store.ListRatePolicies(ctx)
	botConfigs, _ := s.store.ListBotConfigs(ctx)

	resp := UnifiedPolicyDTO{
		Tier1Rate:                100,
		Tier1Burst:               200,
		Tier2Threshold:           10,
		Tier2BanSeconds:          3600,
		Tier3Threshold:           25,
		Tier3BanSeconds:          7200,
		BotDefenseMode:           "defense",
		PowDifficulty:            20000,
		HoneypotEnabled:          true,
		WaitingRoomEnabled:       false,
		WaitingRoomMaxConcurrent: 1000,
		WaitingRoomPaths:         []string{},
	}

	if len(ratePolicies) > 0 {
		rp := ratePolicies[0]
		resp.Tier1Rate = rp.Tier1Rate
		resp.Tier1Burst = rp.Tier1Burst
		resp.Tier2Threshold = rp.Tier2Threshold
		resp.Tier2BanSeconds = rp.Tier2BanDurationSec
		resp.Tier3Threshold = rp.Tier3Threshold
		resp.Tier3BanSeconds = rp.Tier3BanDurationSec
		resp.WaitingRoomEnabled = rp.WaitingRoomEnabled == 1
		resp.WaitingRoomMaxConcurrent = rp.WaitingRoomCapacity
		if rp.WaitingRoomPaths != "" {
			_ = json.Unmarshal([]byte(rp.WaitingRoomPaths), &resp.WaitingRoomPaths)
		}
	}

	if bc := globalBotConfig(botConfigs); bc != nil {
		resp.PowDifficulty = int(bc.PowDifficulty)
		if bc.PowEnabled == 1 {
			resp.BotDefenseMode = "defense"
		} else {
			resp.BotDefenseMode = "audit"
		}
		var traps []string
		_ = json.Unmarshal([]byte(bc.TrapUrls), &traps)
		resp.HoneypotEnabled = len(traps) > 0
	}

	respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateUnifiedPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req UnifiedPolicyDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	ratePolicies, _ := s.store.ListRatePolicies(ctx)
	botConfigs, _ := s.store.ListBotConfigs(ctx)
	now := time.Now().UTC()

	waitingRoomEnabled := int64(0)
	if req.WaitingRoomEnabled {
		waitingRoomEnabled = 1
	}

	wrPathsJSON, _ := json.Marshal(req.WaitingRoomPaths)
	if req.WaitingRoomPaths == nil {
		wrPathsJSON = []byte("[]")
	}

	if s.waitingRoom != nil {
		s.waitingRoom.SetTargetPaths(req.WaitingRoomPaths)
		if req.WaitingRoomMaxConcurrent > 0 {
			s.waitingRoom.SetMaxConcurrent(req.WaitingRoomMaxConcurrent)
		}
	}

	if len(ratePolicies) > 0 {
		_ = s.store.UpdateRatePolicy(ctx, control.RatePolicy{
			ID:                  ratePolicies[0].ID,
			Name:                ratePolicies[0].Name,
			Host:                ratePolicies[0].Host,
			Tier1Rate:           req.Tier1Rate,
			Tier1Burst:          req.Tier1Burst,
			Tier1PeriodSec:      60,
			Tier2Threshold:      req.Tier2Threshold,
			Tier2PeriodSec:      60,
			Tier2BanDurationSec: req.Tier2BanSeconds,
			Tier3Threshold:      req.Tier3Threshold,
			Tier3BanDurationSec: req.Tier3BanSeconds,
			WaitingRoomEnabled:  waitingRoomEnabled,
			WaitingRoomCapacity: req.WaitingRoomMaxConcurrent,
			WaitingRoomPaths:    string(wrPathsJSON),
			IsActive:            1,
			UpdatedAt:           now,
		})
	} else {
		_ = s.store.CreateRatePolicy(ctx, control.RatePolicy{
			ID:                  "policy-default",
			Name:                "Default Rate Policy",
			Host:                "*",
			Tier1Rate:           req.Tier1Rate,
			Tier1Burst:          req.Tier1Burst,
			Tier1PeriodSec:      60,
			Tier2Threshold:      req.Tier2Threshold,
			Tier2PeriodSec:      60,
			Tier2BanDurationSec: req.Tier2BanSeconds,
			Tier3Threshold:      req.Tier3Threshold,
			Tier3BanDurationSec: req.Tier3BanSeconds,
			WaitingRoomEnabled:  waitingRoomEnabled,
			WaitingRoomCapacity: req.WaitingRoomMaxConcurrent,
			WaitingRoomPaths:    string(wrPathsJSON),
			IsActive:            1,
			CreatedAt:           now,
			UpdatedAt:           now,
		})
	}

	powEnabled := int64(0)
	if req.BotDefenseMode == "defense" || req.BotDefenseMode == "challenge" {
		powEnabled = 1
	}
	var traps []string
	if req.HoneypotEnabled {
		traps = []string{"/.raiwall/trap/honeypot", "/admin/login.php", "/wp-login.php"}
	}
	trapsJSON, _ := json.Marshal(traps)

	if global := globalBotConfig(botConfigs); global != nil {
		_ = s.store.UpdateBotConfig(ctx, control.BotConfig{
			ID:            global.ID,
			Host:          global.Host,
			PowEnabled:    powEnabled,
			PowDifficulty: int64(req.PowDifficulty),
			TrapUrls:      string(trapsJSON),
			IsActive:      1,
			UpdatedAt:     now,
		})
	} else {
		_ = s.store.CreateBotConfig(ctx, control.BotConfig{
			ID:            "bot-default",
			Host:          "*",
			PowEnabled:    powEnabled,
			PowDifficulty: int64(req.PowDifficulty),
			TrapUrls:      string(trapsJSON),
			IsActive:      1,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
	}

	respondJSON(w, http.StatusOK, req)
}

// globalBotConfig returns the wildcard bot policy. Global edits must never
// overwrite a per-host override that happens to be first in the list.
func globalBotConfig(configs []control.BotConfig) *control.BotConfig {
	for i := range configs {
		if configs[i].Host == "*" {
			return &configs[i]
		}
	}
	return nil
}

// ReleaseBanRequest represents a request to unblock an IP or ban key.
type ReleaseBanRequest struct {
	Key string `json:"key"`
	IP  string `json:"ip"`
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	if s.banManager == nil {
		respondJSON(w, http.StatusOK, []*rate.BanEntry{})
		return
	}
	bans := s.banManager.ListBans()
	if bans == nil {
		bans = []*rate.BanEntry{}
	}
	respondJSON(w, http.StatusOK, bans)
}

func (s *Server) handleReleaseBan(w http.ResponseWriter, r *http.Request) {
	var req ReleaseBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	target := req.Key
	if target == "" {
		target = req.IP
	}
	if target == "" {
		respondError(w, http.StatusBadRequest, "must specify key or ip to release")
		return
	}

	released := false
	if s.banManager != nil {
		released = s.banManager.Release(target)
	}
	if s.clusterPublisher != nil {
		_ = s.clusterPublisher.PublishUnblock(r.Context(), target)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":   "released",
		"target":   target,
		"released": released,
	})
}

func (s *Server) handleReleaseAllBans(w http.ResponseWriter, r *http.Request) {
	count := 0
	if s.banManager != nil {
		count = s.banManager.ReleaseAll()
	}
	if s.clusterPublisher != nil {
		_ = s.clusterPublisher.PublishUnblockAll(r.Context())
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"status":  "unblocked_all",
		"cleared": count,
	})
}

func (s *Server) handleGetWaitingRoomMetrics(w http.ResponseWriter, r *http.Request) {
	if s.waitingRoom == nil {
		respondJSON(w, http.StatusOK, rate.WaitingRoomMetrics{})
		return
	}
	metrics := s.waitingRoom.Metrics()
	respondJSON(w, http.StatusOK, metrics)
}
