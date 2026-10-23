package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/go-chi/chi/v5"
)

// detectorModuleDTO describes one semantic detection module with its effective global mode.
type detectorModuleDTO struct {
	Module      string `json:"module"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Mode        string `json:"mode"`
}

// detectorAppPolicyDTO represents a per-application semantic override set.
type detectorAppPolicyDTO struct {
	AppID     string            `json:"app_id"`
	Overrides map[string]string `json:"overrides"`
}

// detectorResponse is the payload of GET /api/v1/detector.
type detectorResponse struct {
	Modules   []detectorModuleDTO    `json:"modules"`
	Apps      []detectorAppPolicyDTO `json:"apps"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// detectorModeUpdate is the payload for setting a module's global mode.
type detectorModeUpdate struct {
	Mode string `json:"mode"`
}

// detectorAppPolicyUpdate is the payload for replacing a site's semantic overrides.
type detectorAppPolicyUpdate struct {
	Overrides map[string]string `json:"overrides"`
}

// modeString returns the string mode for a module, defaulting to "balance".
func modeString(snap *control.ConfigSnapshot, module waf.Module) string {
	if snap != nil {
		if mode, ok := snap.SemanticDefaults[module]; ok {
			return mode.String()
		}
	}
	return waf.ModeBalance.String()
}

func (s *Server) handleGetDetector(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.ListDetectorConfig(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list detector config: "+err.Error())
		return
	}

	overrides, err := s.store.ListAppSemanticPolicies(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list app semantic policies: "+err.Error())
		return
	}

	snap := control.LoadSnapshot()

	modules := make([]detectorModuleDTO, 0, len(waf.ModuleRegistry))
	for _, meta := range waf.ModuleRegistry {
		mode := modeString(snap, meta.Module)
		for _, rec := range records {
			if rec.Module == string(meta.Module) {
				mode = rec.Mode
				break
			}
		}
		modules = append(modules, detectorModuleDTO{
			Module:      string(meta.Module),
			Name:        meta.Name,
			Category:    meta.Category,
			Description: meta.Description,
			Mode:        mode,
		})
	}

	apps := make([]detectorAppPolicyDTO, 0, len(overrides))
	for _, rec := range overrides {
		var policy map[waf.Module]waf.ModuleMode
		if rec.Policy != "" {
			_ = json.Unmarshal([]byte(rec.Policy), &policy)
		}
		dtoOverrides := make(map[string]string, len(policy))
		for module, mode := range policy {
			dtoOverrides[string(module)] = mode.String()
		}
		apps = append(apps, detectorAppPolicyDTO{
			AppID:     rec.AppID,
			Overrides: dtoOverrides,
		})
	}

	respondJSON(w, http.StatusOK, detectorResponse{
		Modules: modules,
		Apps:    apps,
	})
}

func (s *Server) handleUpdateDetectorModule(w http.ResponseWriter, r *http.Request) {
	module := waf.Module(chi.URLParam(r, "module"))
	if !waf.IsValidModule(module) {
		respondError(w, http.StatusBadRequest, "unknown semantic module: "+string(module))
		return
	}

	var req detectorModeUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if !waf.IsValidModuleMode(req.Mode) {
		respondError(w, http.StatusBadRequest, "invalid mode (expected disabled, audit, balance, or strict)")
		return
	}

	if err := s.store.UpsertDetectorConfig(r.Context(), control.DetectorConfigRecord{
		Module:    string(module),
		Mode:      req.Mode,
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update detector config: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"module":  string(module),
		"mode":    req.Mode,
	})
}

func (s *Server) handleGetAppPolicy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if _, err := s.store.GetApp(r.Context(), appID); err != nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}

	rec, err := s.findAppPolicy(r, appID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load app semantic policy: "+err.Error())
		return
	}

	overrides := map[string]string{}
	if rec != nil && rec.Policy != "" {
		var policy map[waf.Module]waf.ModuleMode
		if err := json.Unmarshal([]byte(rec.Policy), &policy); err == nil {
			for module, mode := range policy {
				overrides[string(module)] = mode.String()
			}
		}
	}

	respondJSON(w, http.StatusOK, detectorAppPolicyDTO{AppID: appID, Overrides: overrides})
}

func (s *Server) handleUpdateAppPolicy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if _, err := s.store.GetApp(r.Context(), appID); err != nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}

	var req detectorAppPolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	policy := make(map[waf.Module]waf.ModuleMode, len(req.Overrides))
	for rawModule, rawMode := range req.Overrides {
		module := waf.Module(rawModule)
		if !waf.IsValidModule(module) {
			respondError(w, http.StatusBadRequest, "unknown semantic module: "+rawModule)
			return
		}
		if !waf.IsValidModuleMode(rawMode) {
			respondError(w, http.StatusBadRequest, "invalid mode for module "+rawModule+" (expected disabled, audit, balance, or strict)")
			return
		}
		mode, _ := waf.ParseModuleModeString(rawMode)
		policy[module] = mode
	}

	// Empty override set clears the per-app policy row entirely.
	if len(policy) == 0 {
		if err := s.store.DeleteAppSemanticPolicy(r.Context(), appID); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to clear app semantic policy: "+err.Error())
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": appID, "overrides": map[string]string{}})
		return
	}

	encoded, err := json.Marshal(policy)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to serialize policy: "+err.Error())
		return
	}

	if err := s.store.UpsertAppSemanticPolicy(r.Context(), control.AppSemanticPolicyRecord{
		AppID:     appID,
		Policy:    string(encoded),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update app semantic policy: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": appID, "overrides": req.Overrides})
}

// findAppPolicy loads the stored policy record for an app, if present.
func (s *Server) findAppPolicy(r *http.Request, appID string) (*control.AppSemanticPolicyRecord, error) {
	records, err := s.store.ListAppSemanticPolicies(r.Context())
	if err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].AppID == appID {
			return &records[i], nil
		}
	}
	return nil, nil
}
