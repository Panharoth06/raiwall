package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/go-chi/chi/v5"
)

// ruleOverrideRequest changes one catalog rule. Omitted fields are preserved;
// an empty action/severity explicitly clears the override.
type ruleOverrideRequest struct {
	Enabled  *bool   `json:"enabled"`
	Action   *string `json:"action"`
	Severity *string `json:"severity"`
}

type ruleBulkRequest struct {
	IDs      []string `json:"ids"`
	Enabled  *bool    `json:"enabled"`
	Action   *string  `json:"action"`
	Severity *string  `json:"severity"`
}

func (s *Server) handleListDetectionRules(w http.ResponseWriter, r *http.Request) {
	items := control.BuildRuleCatalog(control.GetActiveSnapshot())
	query := control.RuleCatalogQuery{
		Search:   r.URL.Query().Get("q"),
		Source:   r.URL.Query().Get("source"),
		Pack:     r.URL.Query().Get("pack"),
		Category: r.URL.Query().Get("category"),
		Severity: r.URL.Query().Get("severity"),
	}
	if enabledRaw := r.URL.Query().Get("enabled"); enabledRaw != "" {
		enabled, err := strconv.ParseBool(enabledRaw)
		if err != nil {
			respondError(w, http.StatusBadRequest, "enabled must be true or false")
			return
		}
		query.Enabled = &enabled
	}
	query.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	query.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))

	page, total, facets := control.FilterRuleCatalog(items, query)
	respondJSON(w, http.StatusOK, map[string]any{
		"rules":  page,
		"total":  total,
		"offset": maxInt(query.Offset, 0),
		"limit":  normalizeLimit(query.Limit),
		"facets": facets,
	})
}

func (s *Server) handleGetDetectionRule(w http.ResponseWriter, r *http.Request) {
	canonical := chi.URLParam(r, "id")
	item, ok := findCatalogItem(control.GetActiveSnapshot(), canonical)
	if !ok {
		respondError(w, http.StatusNotFound, "unknown detection rule: "+canonical)
		return
	}
	respondJSON(w, http.StatusOK, item)
}

func (s *Server) handleUpdateDetectionRule(w http.ResponseWriter, r *http.Request) {
	canonical := chi.URLParam(r, "id")
	if _, ok := findCatalogItem(control.GetActiveSnapshot(), canonical); !ok {
		respondError(w, http.StatusNotFound, "unknown detection rule: "+canonical)
		return
	}
	var req ruleOverrideRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRuleOverride(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyRuleOverride(r.Context(), canonical, req); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update rule override: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": canonical})
}

func (s *Server) handleResetDetectionRuleOverride(w http.ResponseWriter, r *http.Request) {
	canonical := chi.URLParam(r, "id")
	source, id, err := control.ParseCanonicalRuleID(canonical)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if source == control.RuleSourceSemantic {
		if err := s.store.DeleteDetectorConfig(r.Context(), id); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to reset semantic module: "+err.Error())
			return
		}
	}
	if err := s.store.DeleteRuleOverride(r.Context(), canonical); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to reset rule override: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": canonical})
}

func (s *Server) handleBulkDetectionRules(w http.ResponseWriter, r *http.Request) {
	var req ruleBulkRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		respondError(w, http.StatusBadRequest, "ids must contain at least one rule")
		return
	}
	override := ruleOverrideRequest{Enabled: req.Enabled, Action: req.Action, Severity: req.Severity}
	if err := validateRuleOverride(override); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated := 0
	for _, canonical := range req.IDs {
		if _, ok := findCatalogItem(control.GetActiveSnapshot(), canonical); !ok {
			respondError(w, http.StatusNotFound, "unknown detection rule: "+canonical)
			return
		}
		if err := s.applyRuleOverride(r.Context(), canonical, override); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update "+canonical+": "+err.Error())
			return
		}
		updated++
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "updated": updated})
}

func (s *Server) applyRuleOverride(ctx context.Context, canonical string, req ruleOverrideRequest) error {
	source, id, err := control.ParseCanonicalRuleID(canonical)
	if err != nil {
		return err
	}
	if source == control.RuleSourceSemantic {
		return s.applySemanticOverride(ctx, canonical, id, req)
	}
	return s.applyStoredOverride(ctx, canonical, req)
}

func (s *Server) applySemanticOverride(ctx context.Context, canonical, moduleID string, req ruleOverrideRequest) error {
	module := waf.Module(moduleID)
	if !waf.IsValidModule(module) {
		return fmt.Errorf("unknown semantic module %q", moduleID)
	}
	mode := ""
	if req.Action != nil {
		switch control.NormalizePolicyValue(*req.Action) {
		case "", control.RuleActionInherit:
			mode = ""
		case control.RuleActionOff:
			mode = waf.ModeDisabled.String()
		case control.RuleActionAlert:
			mode = waf.ModeAudit.String()
		case control.RuleActionBlock:
			mode = waf.ModeBalance.String()
		default:
			return fmt.Errorf("unsupported action %q for semantic module", *req.Action)
		}
	}
	if mode == "" && req.Enabled != nil {
		if *req.Enabled {
			mode = waf.ModeBalance.String()
		} else {
			mode = waf.ModeDisabled.String()
		}
	}
	if mode != "" {
		if err := s.store.UpsertDetectorConfig(ctx, control.DetectorConfigRecord{
			Module: moduleID,
			Mode:   mode,
		}); err != nil {
			return err
		}
	} else if req.Action != nil || req.Enabled != nil {
		if err := s.store.DeleteDetectorConfig(ctx, moduleID); err != nil {
			return err
		}
	}

	// Severity overrides use the shared rule-override table; action state for
	// semantic modules lives in the detector matrix.
	if req.Severity != nil && *req.Severity != "" {
		return s.store.UpsertRuleOverride(ctx, control.RuleOverrideRecord{
			CanonicalID: canonical,
			Severity:    *req.Severity,
		})
	}
	if req.Severity != nil {
		return s.store.DeleteRuleOverride(ctx, canonical)
	}
	return nil
}

func (s *Server) applyStoredOverride(ctx context.Context, canonical string, req ruleOverrideRequest) error {
	existing, err := s.store.GetRuleOverride(ctx, canonical)
	if err != nil {
		existing = control.RuleOverrideRecord{CanonicalID: canonical}
	}
	if req.Enabled != nil {
		existing.Enabled = req.Enabled
	}
	if req.Action != nil {
		action := control.NormalizePolicyValue(*req.Action)
		if action == control.RuleActionInherit {
			action = ""
		}
		existing.Action = action
	}
	if req.Severity != nil {
		existing.Severity = *req.Severity
	}
	if existing.Enabled == nil && existing.Action == "" && existing.Severity == "" {
		return s.store.DeleteRuleOverride(ctx, canonical)
	}
	existing.CanonicalID = canonical
	if author, ok := AuthFromContext(ctx); ok && author.Username != "" {
		existing.UpdatedBy = author.Username
	}
	return s.store.UpsertRuleOverride(ctx, existing)
}

func validateRuleOverride(req ruleOverrideRequest) error {
	if req.Action != nil {
		action := control.NormalizePolicyValue(*req.Action)
		if action != "" && !control.IsValidRuleAction(action) {
			return fmt.Errorf("unknown action %q (expected inherit, block, alert, or off)", *req.Action)
		}
	}
	if req.Severity != nil && *req.Severity != "" && !control.IsValidSeverity(*req.Severity) {
		return fmt.Errorf("unknown severity %q", *req.Severity)
	}
	return nil
}

func findCatalogItem(snap *control.ConfigSnapshot, canonical string) (control.RuleCatalogItem, bool) {
	for _, item := range control.BuildRuleCatalog(snap) {
		if item.ID == canonical {
			return item, true
		}
	}
	return control.RuleCatalogItem{}, false
}

func normalizeLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 50
	}
	return limit
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
