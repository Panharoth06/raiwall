package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/go-chi/chi/v5"
)

// innerRuleDTO describes one virtual-patch signature and its effective state.
type innerRuleDTO struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Methods  []string `json:"methods,omitempty"`
	Prefix   string   `json:"prefix,omitempty"`
	Enabled  bool     `json:"enabled"`
	PackID   string   `json:"pack_id,omitempty"`
	PackName string   `json:"pack_name,omitempty"`
}

// innerRuleCategoryDTO groups rule counts per category for filter chips.
type innerRuleCategoryDTO struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Disabled int    `json:"disabled"`
}

// innerRulePluginDTO describes an installed rule pack or plugin feed.
type innerRulePluginDTO struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Type       string    `json:"type"`
	RulesCount int       `json:"rules_count"`
	UpdatedAt  time.Time `json:"updated_at"`
	Status     string    `json:"status"`
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

// innerRuleImportRequest represents a rule pack / plugin feed import payload.
type innerRuleImportRequest struct {
	Name    string          `json:"name"`
	Version string          `json:"version,omitempty"`
	Source  string          `json:"source,omitempty"`
	Rules   []cve.Signature `json:"rules"`
}

func (s *Server) handleListInnerRules(w http.ResponseWriter, r *http.Request) {
	refs, err := s.loadInnerRuleRefs(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load inner rules: "+err.Error())
		return
	}

	dtos := make([]innerRuleDTO, 0, len(refs))
	byCategory := map[string]*innerRuleCategoryDTO{}
	categoryOrder := make([]string, 0, 8)
	for _, ref := range refs {
		dtos = append(dtos, innerRuleDTO{
			ID:       ref.Rule.ID,
			Name:     ref.Rule.Name,
			Category: ref.Rule.Category,
			Severity: control.SeverityForCategory(ref.Rule.Category),
			Methods:  ref.Rule.Methods,
			Prefix:   ref.Rule.Prefix,
			Enabled:  ref.Enabled,
			PackID:   ref.PackID,
			PackName: ref.PackName,
		})
		cat, ok := byCategory[ref.Rule.Category]
		if !ok {
			cat = &innerRuleCategoryDTO{Category: ref.Rule.Category}
			byCategory[ref.Rule.Category] = cat
			categoryOrder = append(categoryOrder, ref.Rule.Category)
		}
		cat.Count++
		if !ref.Enabled {
			cat.Disabled++
		}
	}

	sort.Strings(categoryOrder)
	categories := make([]innerRuleCategoryDTO, 0, len(categoryOrder))
	for _, category := range categoryOrder {
		categories = append(categories, *byCategory[category])
	}

	respondJSON(w, http.StatusOK, innerRulesResponse{
		Rules:      dtos,
		Categories: categories,
		UpdatedAt:  time.Now().UTC(),
	})
}

func (s *Server) handleListInnerRulePlugins(w http.ResponseWriter, r *http.Request) {
	packs, err := s.store.ListRulePacks(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list plugins: "+err.Error())
		return
	}
	rules, _ := cve.BundledRules()
	plugins := []innerRulePluginDTO{{
		ID:         "cve-bundled",
		Name:       "Raiwall Core CVE Virtual Patches",
		Version:    "bundled",
		Type:       "builtin",
		RulesCount: len(rules),
		UpdatedAt:  time.Now().UTC(),
		Status:     "active",
	}}
	for _, pack := range packs {
		status := "disabled"
		if pack.Enabled {
			status = "active"
		}
		plugins = append(plugins, innerRulePluginDTO{
			ID:         pack.ID,
			Name:       pack.Name,
			Version:    pack.Version,
			Type:       pack.Type,
			RulesCount: countPackRules(pack.RulesJSON),
			UpdatedAt:  pack.UpdatedAt,
			Status:     status,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"plugins": plugins})
}

func (s *Server) handleImportInnerRules(w http.ResponseWriter, r *http.Request) {
	var req innerRuleImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid rule pack JSON: "+err.Error())
		return
	}
	if len(req.Rules) == 0 {
		respondError(w, http.StatusBadRequest, "rule pack contains no signature rules")
		return
	}
	for i := range req.Rules {
		if req.Rules[i].Category == "" {
			req.Rules[i].Category = "cve"
		}
	}
	if _, err := cve.NewEngine(req.Rules); err != nil {
		respondError(w, http.StatusBadRequest, "invalid signature pack: "+err.Error())
		return
	}
	pluginName := strings.TrimSpace(req.Name)
	if pluginName == "" {
		pluginName = fmt.Sprintf("External Rule Pack (%s)", time.Now().Format("2006-01-02"))
	}
	record, err := s.createNativePack(r.Context(), pluginName, req.Version, req.Rules)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		}
		respondError(w, status, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"plugin": innerRulePluginDTO{
			ID:         record.ID,
			Name:       record.Name,
			Version:    record.Version,
			Type:       record.Type,
			RulesCount: len(req.Rules),
			UpdatedAt:  record.UpdatedAt,
			Status:     "installed",
		},
		"imported_rules": len(req.Rules),
		"message":        fmt.Sprintf("Imported %d rule(s) from %s", len(req.Rules), pluginName),
	})
}

func (s *Server) handleUpdateInnerRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "id")
	ref, ok, err := s.findInnerRuleRef(r.Context(), ruleID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to resolve rule: "+err.Error())
		return
	}
	if !ok {
		respondError(w, http.StatusNotFound, "unknown inner rule: "+ruleID)
		return
	}
	var req innerRuleUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := s.setInnerRuleEnabled(r.Context(), ref, req.Enabled); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update inner rule state: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": ruleID, "enabled": req.Enabled})
}

func (s *Server) handleUpdateInnerRuleCategory(w http.ResponseWriter, r *http.Request) {
	category := chi.URLParam(r, "category")
	var req innerRuleBatchUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	refs, err := s.loadInnerRuleRefs(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load inner rules: "+err.Error())
		return
	}
	matched := 0
	for _, ref := range refs {
		if ref.Rule.Category != category {
			continue
		}
		matched++
		if err := s.setInnerRuleEnabled(r.Context(), ref, req.Enabled); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update inner rule state: "+err.Error())
			return
		}
	}
	if matched == 0 {
		respondError(w, http.StatusNotFound, "category has no rules: "+category)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"success": true, "category": category, "enabled": req.Enabled, "count": matched,
	})
}

func (s *Server) setInnerRuleEnabled(ctx context.Context, ref innerRuleRef, enabled bool) error {
	action := ""
	if !enabled {
		action = control.RuleActionOff
	}
	return s.store.UpsertRuleOverride(ctx, control.RuleOverrideRecord{
		CanonicalID: ref.Canonical,
		Enabled:     &enabled,
		Action:      action,
	})
}
