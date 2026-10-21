package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ForwardingRuleDTO represents path prefix routing to custom backends.
type ForwardingRuleDTO struct {
	ID                 string                  `json:"id"`
	AppID              string                  `json:"app_id"`
	Prefix             string                  `json:"prefix"`
	Upstreams          []control.UpstreamTarget `json:"upstreams"`
	StripPrefix        bool                    `json:"strip_prefix"`
	HostHeaderOverride string                  `json:"host_header_override"`
	Comment            string                  `json:"comment"`
	IsActive           bool                    `json:"is_active"`
	CreatedAt          time.Time               `json:"created_at"`
	UpdatedAt          time.Time               `json:"updated_at"`
}

// APIResourceDTO represents auto-discovered endpoint metadata.
type APIResourceDTO struct {
	ID          string    `json:"id"`
	AppID       string    `json:"app_id"`
	Method      string    `json:"method"`
	PathPattern string    `json:"path_pattern"`
	ContentType string    `json:"content_type"`
	HitCount    int64     `json:"hit_count"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) handleListForwardingRules(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	rules, err := s.store.ListForwardingRulesByApp(r.Context(), siteID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list forwarding rules: "+err.Error())
		return
	}

	result := make([]ForwardingRuleDTO, 0, len(rules))
	for _, rule := range rules {
		var upstreams []control.UpstreamTarget
		if rule.Upstreams != "" {
			_ = json.Unmarshal([]byte(rule.Upstreams), &upstreams)
		}
		result = append(result, ForwardingRuleDTO{
			ID:                 rule.ID,
			AppID:              rule.AppID,
			Prefix:             rule.Prefix,
			Upstreams:          upstreams,
			StripPrefix:        rule.StripPrefix == 1,
			HostHeaderOverride: rule.HostHeaderOverride,
			Comment:            rule.Comment,
			IsActive:           rule.IsActive == 1,
			CreatedAt:          rule.CreatedAt,
			UpdatedAt:          rule.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateForwardingRule(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	var req ForwardingRuleDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ID == "" {
		req.ID = "fwd-" + uuid.New().String()[:8]
	}
	req.AppID = siteID
	if req.Prefix == "" {
		req.Prefix = "/"
	}

	upstreamsJSON, _ := json.Marshal(req.Upstreams)
	var stripPrefix, isActive int64
	if req.StripPrefix {
		stripPrefix = 1
	}
	if req.IsActive {
		isActive = 1
	}
	now := time.Now().UTC()

	err := s.store.CreateForwardingRule(r.Context(), control.ForwardingRuleRecord{
		ID:                 req.ID,
		AppID:              siteID,
		Prefix:             req.Prefix,
		Upstreams:          string(upstreamsJSON),
		StripPrefix:        stripPrefix,
		HostHeaderOverride: req.HostHeaderOverride,
		Comment:            req.Comment,
		IsActive:           isActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create forwarding rule: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateForwardingRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "rule_id")
	var req ForwardingRuleDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	upstreamsJSON, _ := json.Marshal(req.Upstreams)
	var stripPrefix, isActive int64
	if req.StripPrefix {
		stripPrefix = 1
	}
	if req.IsActive {
		isActive = 1
	}
	now := time.Now().UTC()

	err := s.store.UpdateForwardingRule(r.Context(), control.ForwardingRuleRecord{
		ID:                 ruleID,
		Prefix:             req.Prefix,
		Upstreams:          string(upstreamsJSON),
		StripPrefix:        stripPrefix,
		HostHeaderOverride: req.HostHeaderOverride,
		Comment:            req.Comment,
		IsActive:           isActive,
		UpdatedAt:          now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update forwarding rule: "+err.Error())
		return
	}

	req.ID = ruleID
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteForwardingRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "rule_id")
	err := s.store.DeleteForwardingRule(r.Context(), ruleID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete forwarding rule: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": ruleID})
}

func (s *Server) handleListAPIResources(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "id")
	resources, err := s.store.ListAPIResourcesByApp(r.Context(), siteID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list api resources: "+err.Error())
		return
	}

	result := make([]APIResourceDTO, 0, len(resources))
	for _, res := range resources {
		result = append(result, APIResourceDTO{
			ID:          res.ID,
			AppID:       res.AppID,
			Method:      res.Method,
			PathPattern: res.PathPattern,
			ContentType: res.ContentType,
			HitCount:    res.HitCount,
			LastSeen:    res.LastSeen,
			CreatedAt:   res.CreatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteAPIResource(w http.ResponseWriter, r *http.Request) {
	resourceID := chi.URLParam(r, "resource_id")
	err := s.store.DeleteAPIResource(r.Context(), resourceID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete api resource: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": resourceID})
}
