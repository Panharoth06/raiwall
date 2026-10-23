package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/go-chi/chi/v5"
)

// innerRuleDTO describes one virtual-patch signature and its effective state.
type innerRuleDTO struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Enabled  bool   `json:"enabled"`
}

// innerRuleCategoryDTO groups rule counts per category for filter chips.
type innerRuleCategoryDTO struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Disabled int    `json:"disabled"`
}

// innerRulesResponse is the payload of GET /api/v1/inner-rules.
type innerRulesResponse struct {
	Rules      []innerRuleDTO         `json:"rules"`
	Categories []innerRuleCategoryDTO `json:"categories"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// innerRuleUpdate is the payload for toggling one rule.
type innerRuleUpdate struct {
	Enabled bool `json:"enabled"`
}

// innerRuleBatchUpdate is the payload for toggling a whole category.
type innerRuleBatchUpdate struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleListInnerRules(w http.ResponseWriter, r *http.Request) {
	disabled, err := s.store.ListDisabledInnerRules(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list inner rules state: "+err.Error())
		return
	}
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, id := range disabled {
		disabledSet[id] = struct{}{}
	}

	rules, err := cve.BundledRules()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load rule library: "+err.Error())
		return
	}

	dtos := make([]innerRuleDTO, 0, len(rules))
	byCategory := map[string]*innerRuleCategoryDTO{}
	categoryOrder := make([]string, 0, 8)
	for _, rule := range rules {
		_, off := disabledSet[rule.ID]
		dtos = append(dtos, innerRuleDTO{
			ID:       rule.ID,
			Name:     rule.Name,
			Category: rule.Category,
			Enabled:  !off,
		})
		cat, ok := byCategory[rule.Category]
		if !ok {
			cat = &innerRuleCategoryDTO{Category: rule.Category}
			byCategory[rule.Category] = cat
			categoryOrder = append(categoryOrder, rule.Category)
		}
		cat.Count++
		if off {
			cat.Disabled++
		}
	}
	categories := make([]innerRuleCategoryDTO, 0, len(categoryOrder))
	for _, c := range categoryOrder {
		categories = append(categories, *byCategory[c])
	}

	respondJSON(w, http.StatusOK, innerRulesResponse{Rules: dtos, Categories: categories})
}

func (s *Server) handleUpdateInnerRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "id")

	rule, ok := bundledRule(ruleID)
	if !ok {
		respondError(w, http.StatusNotFound, "unknown inner rule: "+ruleID)
		return
	}

	var req innerRuleUpdate
	// NOTE: decode into a fresh struct — reusable decoders leak stale fields.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if err := s.store.SetInnerRuleDisabled(r.Context(), rule.ID, !req.Enabled); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update inner rule state: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": rule.ID, "enabled": req.Enabled})
}

func (s *Server) handleUpdateInnerRuleCategory(w http.ResponseWriter, r *http.Request) {
	category := chi.URLParam(r, "category")

	rules, err := cve.BundledRules()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load rule library: "+err.Error())
		return
	}

	var req innerRuleBatchUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	matched := 0
	for _, rule := range rules {
		if rule.Category != category {
			continue
		}
		matched++
		if err := s.store.SetInnerRuleDisabled(r.Context(), rule.ID, !req.Enabled); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update inner rule state: "+err.Error())
			return
		}
	}
	if matched == 0 {
		respondError(w, http.StatusNotFound, "category has no rules: "+category)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "category": category, "enabled": req.Enabled, "count": matched})
}

// bundledRule looks up a signature by ID from the embedded library.
func bundledRule(id string) (*cve.Signature, bool) {
	rules, err := cve.BundledRules()
	if err != nil {
		return nil, false
	}
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i], true
		}
	}
	return nil, false
}
