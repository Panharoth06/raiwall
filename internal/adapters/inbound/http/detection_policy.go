package api

import (
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/go-chi/chi/v5"
)

// crsPolicyDTO is the CRS tuning block of a detection policy.
type crsPolicyDTO struct {
	Enabled           *bool `json:"enabled,omitempty"`
	ParanoiaLevel     int   `json:"paranoia_level,omitempty"`
	InboundThreshold  int   `json:"inbound_threshold,omitempty"`
	OutboundThreshold int   `json:"outbound_threshold,omitempty"`
}

// dlpPolicyDTO is the DLP tuning block of an outbound response policy.
type dlpPolicyDTO struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	Action            string `json:"action,omitempty"`
	DetectPAN         *bool  `json:"detect_pan,omitempty"`
	DetectSecrets     *bool  `json:"detect_secrets,omitempty"`
	DetectJWT         *bool  `json:"detect_jwt,omitempty"`
	DetectPrivateKeys *bool  `json:"detect_private_keys,omitempty"`
	Redaction         string `json:"redaction,omitempty"`
	MaxScanBytes      int    `json:"max_scan_bytes,omitempty"`
}

// responsePolicyDTO is the outbound inspection tuning block of a detection policy.
type responsePolicyDTO struct {
	Enabled          *bool         `json:"enabled,omitempty"`
	Mode             string        `json:"mode,omitempty"`
	InspectHeaders   *bool         `json:"inspect_headers,omitempty"`
	InspectBody      *bool         `json:"inspect_body,omitempty"`
	BodyLimit        int           `json:"body_limit,omitempty"`
	HardCap          int           `json:"hard_cap,omitempty"`
	Decompress       *bool         `json:"decompress,omitempty"`
	ContentTypes     []string      `json:"content_types,omitempty"`
	MaxInflightBytes int64         `json:"max_inflight_bytes,omitempty"`
	DLP              *dlpPolicyDTO `json:"dlp,omitempty"`
}

// wafPolicyDTO is the API representation of a global or per-site policy.
type wafPolicyDTO struct {
	DetectionMode     string             `json:"detection_mode"`
	Sensitivity       string             `json:"sensitivity"`
	SemanticOverrides map[string]string  `json:"semantic_overrides,omitempty"`
	CRS               *crsPolicyDTO      `json:"crs,omitempty"`
	DisabledPacks     []string           `json:"disabled_packs,omitempty"`
	Response          *responsePolicyDTO `json:"response,omitempty"`
}

// detectionStatusDTO summarizes the active detection posture.
type detectionStatusDTO struct {
	SnapshotVersion    uint64   `json:"snapshot_version"`
	DetectionMode      string   `json:"detection_mode"`
	Sensitivity        string   `json:"sensitivity"`
	CRSEnabled         bool     `json:"crs_enabled"`
	CRSEngineAvailable bool     `json:"crs_engine_available"`
	RulePacks          int      `json:"rule_packs"`
	RuleOverrides      int      `json:"rule_overrides"`
	Exceptions         int      `json:"exceptions"`
	DisabledRules      int      `json:"disabled_rules"`
	Sources            []string `json:"sources"`
}

func (s *Server) handleGetDetectionStatus(w http.ResponseWriter, r *http.Request) {
	snap := control.GetActiveSnapshot()
	status := detectionStatusDTO{
		DetectionMode: control.DetectionModeInherit,
		Sensitivity:   control.SensitivityInherit,
		Sources:       []string{control.RuleSourceSemantic, control.RuleSourceCVE, control.RuleSourceCRS, control.RuleSourcePack},
	}
	if snap == nil {
		respondJSON(w, http.StatusOK, status)
		return
	}
	policy := snap.ResolveWAFPolicyFor("")
	status.SnapshotVersion = snap.Version
	if mode := control.NormalizePolicyValue(policy.DetectionMode); mode != "" {
		status.DetectionMode = mode
	}
	if sensitivity := control.NormalizePolicyValue(policy.Sensitivity); sensitivity != "" {
		status.Sensitivity = sensitivity
	}
	if policy.CRSEnabled != nil {
		status.CRSEnabled = *policy.CRSEnabled
	} else {
		status.CRSEnabled = s.crsDefaultEnabled
	}
	status.CRSEngineAvailable = s.crsEngineAvailable
	status.RulePacks = len(snap.RulePacks)
	status.RuleOverrides = len(snap.RuleOverrides)
	status.Exceptions = len(snap.Exceptions)
	status.DisabledRules = len(snap.InnerRulesDisabled)
	respondJSON(w, http.StatusOK, status)
}

func (s *Server) handleListDetectionPresets(w http.ResponseWriter, _ *http.Request) {
	presets := []map[string]any{
		presetDTO(control.SensitivityLow, "Low: high-confidence detectors enforce; heuristic logic/protocol modules audit."),
		presetDTO(control.SensitivityMedium, "Medium: production default; every module balances confident detections."),
		presetDTO(control.SensitivityHigh, "High: every module blocks on any detection signal; CRS paranoia level 2."),
	}
	respondJSON(w, http.StatusOK, map[string]any{"presets": presets})
}

func presetDTO(sensitivity, description string) map[string]any {
	matrix := map[string]string{}
	expanded := waf.MatrixForSensitivity(sensitivity)
	for _, meta := range waf.ModuleRegistry {
		matrix[string(meta.Module)] = expanded.Mode(meta.Module).String()
	}
	crs := map[string]any{"paranoia_level": 1, "inbound_threshold": 5, "outbound_threshold": 4}
	switch sensitivity {
	case control.SensitivityLow:
		crs = map[string]any{"paranoia_level": 1, "inbound_threshold": 10, "outbound_threshold": 8}
	case control.SensitivityHigh:
		crs = map[string]any{"paranoia_level": 2, "inbound_threshold": 3, "outbound_threshold": 2}
	}
	return map[string]any{"id": sensitivity, "description": description, "modules": matrix, "crs": crs}
}

func (s *Server) handleGetDetectionPolicy(w http.ResponseWriter, r *http.Request) {
	snap := control.GetActiveSnapshot()
	raw := control.WAFPolicySnapshot{}
	if snap != nil && snap.WAFPolicy != nil {
		raw = *snap.WAFPolicy
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"policy":   wafPolicyToDTO(raw),
		"resolved": wafPolicyToDTO(s.resolvePolicyDefaults(raw)),
	})
}

// resolvePolicyDefaults fills unset CRS and Response fields from the process configuration.
func (s *Server) resolvePolicyDefaults(policy control.WAFPolicySnapshot) control.WAFPolicySnapshot {
	resolved := policy
	if resolved.CRSEnabled == nil {
		enabled := s.crsDefaultEnabled
		resolved.CRSEnabled = &enabled
	}
	if resolved.CRSParanoiaLevel <= 0 {
		resolved.CRSParanoiaLevel = s.crsDefaultParanoia
	}
	if resolved.CRSInboundThreshold <= 0 {
		resolved.CRSInboundThreshold = s.crsDefaultInbound
	}
	if resolved.CRSOutboundThreshold <= 0 {
		resolved.CRSOutboundThreshold = s.crsDefaultOutbound
	}

	defaultResp := control.DefaultResponsePolicySnapshot()
	if resolved.Response == nil {
		resolved.Response = defaultResp
	} else {
		base := control.DefaultResponsePolicySnapshot()
		control.OverlayResponsePolicy(base, resolved.Response)
		resolved.Response = base
	}

	return resolved
}

func (s *Server) handleUpdateDetectionPolicy(w http.ResponseWriter, r *http.Request) {
	var req wafPolicyDTO
	if err := decodeJSONBody(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePolicyDTO(&req, control.GetActiveSnapshot()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := policyRecordFromDTO(req, "global", control.PolicyScopeGlobal, "")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertWAFPolicy(r.Context(), rec); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save detection policy: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "policy": wafPolicyToDTO(policyFromDTO(req))})
}

func (s *Server) handleListAppDetectionPolicies(w http.ResponseWriter, r *http.Request) {
	snap := control.GetActiveSnapshot()
	if snap == nil {
		respondJSON(w, http.StatusOK, map[string]any{"policies": []any{}})
		return
	}
	type appPolicyDTO struct {
		AppID      string       `json:"app_id"`
		Name       string       `json:"name"`
		Policy     wafPolicyDTO `json:"policy"`
		Raw        wafPolicyDTO `json:"raw"`
		Overridden bool         `json:"overridden"`
	}
	policies := make([]appPolicyDTO, 0, len(snap.Apps))
	for appID, app := range snap.Apps {
		if app == nil {
			continue
		}
		raw := control.WAFPolicySnapshot{}
		if app.WAFPolicy != nil {
			raw = *app.WAFPolicy
		}
		policies = append(policies, appPolicyDTO{
			AppID:      appID,
			Name:       app.Name,
			Policy:     wafPolicyToDTO(snap.ResolveWAFPolicyFor(appID)),
			Raw:        wafPolicyToDTO(raw),
			Overridden: app.WAFPolicy != nil,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (s *Server) handleGetAppDetectionPolicy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	app, err := s.store.GetApp(r.Context(), appID)
	if err != nil {
		respondError(w, http.StatusNotFound, "unknown application: "+appID)
		return
	}
	snap := control.GetActiveSnapshot()
	resolved := control.WAFPolicySnapshot{}
	raw := control.WAFPolicySnapshot{}
	if snap != nil {
		resolved = snap.ResolveWAFPolicyFor(appID)
		if appCfg := snap.Apps[appID]; appCfg != nil && appCfg.WAFPolicy != nil {
			raw = *appCfg.WAFPolicy
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"app_id":   appID,
		"name":     app.Name,
		"policy":   wafPolicyToDTO(raw),
		"resolved": wafPolicyToDTO(resolved),
	})
}

func (s *Server) handleUpdateAppDetectionPolicy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if _, err := s.store.GetApp(r.Context(), appID); err != nil {
		respondError(w, http.StatusNotFound, "unknown application: "+appID)
		return
	}
	var req wafPolicyDTO
	if err := decodeJSONBody(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePolicyDTO(&req, control.GetActiveSnapshot()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := policyRecordFromDTO(req, "app:"+appID, control.PolicyScopeApp, appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertWAFPolicy(r.Context(), rec); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save site detection policy: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "policy": wafPolicyToDTO(policyFromDTO(req))})
}

func (s *Server) handleDeleteAppDetectionPolicy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "id")
	if err := s.store.DeleteWAFPolicy(r.Context(), control.PolicyScopeApp, appID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to reset site detection policy: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": appID})
}
