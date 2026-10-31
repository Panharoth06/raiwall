package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// rulePackPayload is the import/validate payload for an external rule pack.
// ModSecurity and CRS packs are accepted by the schema but only native packs
// are executable until the SecRule engine lands.
type rulePackPayload struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Type       string            `json:"type"`
	Relation   string            `json:"relation"`
	Priority   int               `json:"priority"`
	Rules      []cve.Signature   `json:"rules,omitempty"`
	Directives string            `json:"directives,omitempty"`
	Files      map[string]string `json:"files,omitempty"`
}

type rulePackDTO struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Type       string    `json:"type"`
	Relation   string    `json:"relation"`
	Enabled    bool      `json:"enabled"`
	Priority   int       `json:"priority"`
	RulesCount int       `json:"rules_count"`
	Status     string    `json:"status"`
	Builtin    bool      `json:"builtin,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type rulePackUpdate struct {
	Enabled  *bool `json:"enabled"`
	Priority *int  `json:"priority"`
}

func (s *Server) handleListDetectionPacks(w http.ResponseWriter, r *http.Request) {
	packs, err := s.store.ListRulePacks(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list rule packs: "+err.Error())
		return
	}
	dtos := []rulePackDTO{builtinCVEPack()}
	for _, pack := range packs {
		dtos = append(dtos, packDTOFromRecord(pack))
	}
	respondJSON(w, http.StatusOK, map[string]any{"packs": dtos})
}

func (s *Server) handleValidateDetectionPack(w http.ResponseWriter, r *http.Request) {
	var payload rulePackPayload
	if err := decodeJSONBody(w, r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := validateRulePack(payload)
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateDetectionPack(w http.ResponseWriter, r *http.Request) {
	var payload rulePackPayload
	if err := decodeJSONBody(w, r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := validateRulePack(payload)
	if !result.Valid {
		respondJSON(w, http.StatusUnprocessableEntity, result)
		return
	}
	var (
		record control.RulePackRecord
		err    error
	)
	if payload.Type == control.PackTypeNative {
		record, err = s.createNativePack(r.Context(), payload.Name, payload.Version, payload.Rules)
	} else {
		record, err = s.createModsecPack(r.Context(), payload)
	}
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		respondError(w, http.StatusInternalServerError, "failed to install rule pack: "+err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{"success": true, "pack": packDTOFromRecord(record)})
}

func (s *Server) handleUpdateDetectionPack(w http.ResponseWriter, r *http.Request) {
	packID := chi.URLParam(r, "id")
	record, err := s.store.GetRulePack(r.Context(), packID)
	if err != nil {
		respondError(w, http.StatusNotFound, "unknown rule pack: "+packID)
		return
	}
	var req rulePackUpdate
	if err := decodeJSONBody(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Enabled != nil {
		record.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		record.Priority = *req.Priority
	}
	if err := s.store.UpsertRulePack(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update rule pack: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "pack": packDTOFromRecord(record)})
}

func (s *Server) handleDeleteDetectionPack(w http.ResponseWriter, r *http.Request) {
	packID := chi.URLParam(r, "id")
	if _, err := s.store.GetRulePack(r.Context(), packID); err != nil {
		respondError(w, http.StatusNotFound, "unknown rule pack: "+packID)
		return
	}
	prefix := control.CanonicalRuleID(control.RuleSourcePack, packID+":")
	overrides, err := s.store.ListRuleOverrides(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list rule overrides: "+err.Error())
		return
	}
	for _, override := range overrides {
		if strings.HasPrefix(override.CanonicalID, prefix) {
			if err := s.store.DeleteRuleOverride(r.Context(), override.CanonicalID); err != nil {
				respondError(w, http.StatusInternalServerError, "failed to remove pack overrides: "+err.Error())
				return
			}
		}
	}
	if err := s.store.DeleteRulePack(r.Context(), packID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete rule pack: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": packID})
}

func (s *Server) createNativePack(ctx context.Context, name, version string, rules []cve.Signature) (control.RulePackRecord, error) {
	if strings.TrimSpace(version) == "" {
		version = "1.0.0"
	}
	existing, err := s.store.ListRulePacks(ctx)
	if err != nil {
		return control.RulePackRecord{}, err
	}
	for _, pack := range existing {
		if pack.Name == name && pack.Version == version {
			return control.RulePackRecord{}, fmt.Errorf("pack %q version %q already exists", name, version)
		}
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return control.RulePackRecord{}, fmt.Errorf("encode rules: %w", err)
	}
	sum := sha256.Sum256(rulesJSON)
	record := control.RulePackRecord{
		ID:        "pack-" + uuid.NewString(),
		Name:      name,
		Version:   version,
		Type:      control.PackTypeNative,
		Priority:  100,
		Enabled:   true,
		RulesJSON: string(rulesJSON),
		FilesJSON: "{}",
		Checksum:  hex.EncodeToString(sum[:]),
	}
	if err := s.store.UpsertRulePack(ctx, record); err != nil {
		return control.RulePackRecord{}, err
	}
	return record, nil
}

func (s *Server) createModsecPack(ctx context.Context, payload rulePackPayload) (control.RulePackRecord, error) {
	existing, err := s.store.ListRulePacks(ctx)
	if err != nil {
		return control.RulePackRecord{}, err
	}
	version := payload.Version
	if strings.TrimSpace(version) == "" {
		version = "1.0.0"
	}
	for _, pack := range existing {
		if pack.Name == payload.Name && pack.Version == version {
			return control.RulePackRecord{}, fmt.Errorf("pack %q version %q already exists", payload.Name, version)
		}
	}
	filesJSON, err := json.Marshal(payload.Files)
	if err != nil {
		return control.RulePackRecord{}, fmt.Errorf("encode pack files: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(payload.Directives))
	for name, content := range payload.Files {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte(content))
	}
	record := control.RulePackRecord{
		ID:             "pack-" + uuid.NewString(),
		Name:           payload.Name,
		Version:        version,
		Type:           payload.Type,
		Priority:       normalizePackPriority(payload.Priority),
		Enabled:        true,
		ReplaceBuiltin: payload.Relation == control.PackRelationReplace,
		RulesJSON:      "[]",
		Directives:     payload.Directives,
		FilesJSON:      string(filesJSON),
		Checksum:       hex.EncodeToString(hash.Sum(nil)),
	}
	if err := s.store.UpsertRulePack(ctx, record); err != nil {
		return control.RulePackRecord{}, err
	}
	return record, nil
}

func builtinCVEPack() rulePackDTO {
	rules, _ := cve.BundledRules()
	return rulePackDTO{
		ID:         "cve-bundled",
		Name:       "Raiwall Core CVE Virtual Patches",
		Version:    "bundled",
		Type:       "builtin",
		Relation:   control.PackRelationAdditive,
		Enabled:    true,
		Priority:   0,
		RulesCount: len(rules),
		Status:     "builtin",
		Builtin:    true,
		UpdatedAt:  time.Now().UTC(),
	}
}

func packDTOFromRecord(record control.RulePackRecord) rulePackDTO {
	rules, _ := decodeNativeRuleCount(record.RulesJSON)
	if record.Type != control.PackTypeNative {
		rules = countModsecRules(record.Directives, record.FilesJSON)
	}
	relation := control.PackRelationAdditive
	if record.ReplaceBuiltin {
		relation = control.PackRelationReplace
	}
	status := "disabled"
	if record.Enabled {
		status = "active"
	}
	return rulePackDTO{
		ID:         record.ID,
		Name:       record.Name,
		Version:    record.Version,
		Type:       record.Type,
		Relation:   relation,
		Enabled:    record.Enabled,
		Priority:   record.Priority,
		RulesCount: rules,
		Status:     status,
		UpdatedAt:  record.UpdatedAt,
	}
}
