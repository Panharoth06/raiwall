package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func validatePolicyDTO(req *wafPolicyDTO, snap *control.ConfigSnapshot) error {
	mode := control.NormalizePolicyValue(req.DetectionMode)
	if mode != "" && !control.IsValidDetectionMode(mode) {
		return fmt.Errorf("unknown detection_mode %q (expected off, alert, block, or inherit)", req.DetectionMode)
	}
	sensitivity := control.NormalizePolicyValue(req.Sensitivity)
	if sensitivity != "" && !control.IsValidSensitivity(sensitivity) {
		return fmt.Errorf("unknown sensitivity %q (expected low, medium, high, or inherit)", req.Sensitivity)
	}
	for module, modeString := range req.SemanticOverrides {
		if !waf.IsValidModule(waf.Module(module)) {
			return fmt.Errorf("unknown semantic module %q", module)
		}
		if !waf.IsValidModuleMode(modeString) {
			return fmt.Errorf("unknown mode %q for module %q", modeString, module)
		}
	}
	if req.CRS != nil {
		if req.CRS.ParanoiaLevel < 0 || req.CRS.ParanoiaLevel > 4 {
			return fmt.Errorf("crs.paranoia_level must be between 0 and 4")
		}
		if req.CRS.InboundThreshold < 0 || req.CRS.OutboundThreshold < 0 {
			return fmt.Errorf("crs thresholds cannot be negative")
		}
	}
	if req.Response != nil {
		if req.Response.Mode != "" && !control.IsValidResponseMode(req.Response.Mode) {
			return fmt.Errorf("unknown response mode %q (expected inherit, audit, redact, or block)", req.Response.Mode)
		}
		if req.Response.BodyLimit < 0 || req.Response.HardCap < 0 {
			return fmt.Errorf("response limits cannot be negative")
		}
		if req.Response.DLP != nil {
			if req.Response.DLP.Action != "" && !control.IsValidResponseMode(req.Response.DLP.Action) {
				return fmt.Errorf("unknown dlp action %q (expected inherit, audit, redact, or block)", req.Response.DLP.Action)
			}
			if req.Response.DLP.MaxScanBytes < 0 {
				return fmt.Errorf("dlp max_scan_bytes cannot be negative")
			}
		}
	}
	if snap != nil {
		for _, packID := range req.DisabledPacks {
			found := false
			for _, pack := range snap.RulePacks {
				if pack != nil && pack.ID == packID {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("unknown pack %q", packID)
			}
		}
	}
	return nil
}

func policyRecordFromDTO(req wafPolicyDTO, id, scope, appID string) (control.WAFPolicyRecord, error) {
	semantic := req.SemanticOverrides
	if semantic == nil {
		semantic = map[string]string{}
	}
	semanticJSON, err := json.Marshal(semantic)
	if err != nil {
		return control.WAFPolicyRecord{}, fmt.Errorf("encode semantic_overrides: %w", err)
	}
	packs := req.DisabledPacks
	if packs == nil {
		packs = []string{}
	}
	packsJSON, err := json.Marshal(packs)
	if err != nil {
		return control.WAFPolicyRecord{}, fmt.Errorf("encode disabled_packs: %w", err)
	}
	respJSON := "{}"
	if req.Response != nil {
		bytes, err := json.Marshal(req.Response)
		if err != nil {
			return control.WAFPolicyRecord{}, fmt.Errorf("encode response: %w", err)
		}
		respJSON = string(bytes)
	}
	rec := control.WAFPolicyRecord{
		ID:                id,
		Scope:             scope,
		AppID:             appID,
		DetectionMode:     control.NormalizePolicyValue(req.DetectionMode),
		Sensitivity:       control.NormalizePolicyValue(req.Sensitivity),
		SemanticOverrides: string(semanticJSON),
		DisabledPackIDs:   string(packsJSON),
		ResponseJSON:      respJSON,
	}
	if rec.DetectionMode == "" {
		rec.DetectionMode = control.DetectionModeInherit
	}
	if rec.Sensitivity == "" {
		rec.Sensitivity = control.SensitivityInherit
	}
	if req.CRS != nil {
		rec.CRSEnabled = req.CRS.Enabled
		if req.CRS.ParanoiaLevel > 0 {
			pl := req.CRS.ParanoiaLevel
			rec.CRSParanoiaLevel = &pl
		}
		if req.CRS.InboundThreshold > 0 {
			in := req.CRS.InboundThreshold
			rec.CRSInboundThreshold = &in
		}
		if req.CRS.OutboundThreshold > 0 {
			out := req.CRS.OutboundThreshold
			rec.CRSOutboundThreshold = &out
		}
	}
	return rec, nil
}

func policyFromDTO(req wafPolicyDTO) control.WAFPolicySnapshot {
	policy := control.WAFPolicySnapshot{
		DetectionMode: control.NormalizePolicyValue(req.DetectionMode),
		Sensitivity:   control.NormalizePolicyValue(req.Sensitivity),
		DisabledPacks: append([]string(nil), req.DisabledPacks...),
		Response:      responseSnapshotFromDTO(req.Response),
	}
	if len(req.SemanticOverrides) > 0 {
		policy.SemanticOverrides = make(map[waf.Module]waf.ModuleMode, len(req.SemanticOverrides))
		for module, mode := range req.SemanticOverrides {
			parsed, err := waf.ParseModuleModeString(mode)
			if err == nil {
				policy.SemanticOverrides[waf.Module(module)] = parsed
			}
		}
	}
	if req.CRS != nil {
		policy.CRSEnabled = req.CRS.Enabled
		policy.CRSParanoiaLevel = req.CRS.ParanoiaLevel
		policy.CRSInboundThreshold = req.CRS.InboundThreshold
		policy.CRSOutboundThreshold = req.CRS.OutboundThreshold
	}
	return policy
}

func wafPolicyToDTO(policy control.WAFPolicySnapshot) wafPolicyDTO {
	dto := wafPolicyDTO{
		DetectionMode: policy.DetectionMode,
		Sensitivity:   policy.Sensitivity,
		Response:      responseDTOFromSnapshot(policy.Response),
	}
	if dto.DetectionMode == "" {
		dto.DetectionMode = control.DetectionModeInherit
	}
	if dto.Sensitivity == "" {
		dto.Sensitivity = control.SensitivityInherit
	}
	if len(policy.SemanticOverrides) > 0 {
		dto.SemanticOverrides = make(map[string]string, len(policy.SemanticOverrides))
		for module, mode := range policy.SemanticOverrides {
			dto.SemanticOverrides[string(module)] = mode.String()
		}
	}
	if policy.CRSEnabled != nil || policy.CRSParanoiaLevel > 0 ||
		policy.CRSInboundThreshold > 0 || policy.CRSOutboundThreshold > 0 {
		dto.CRS = &crsPolicyDTO{
			Enabled:           policy.CRSEnabled,
			ParanoiaLevel:     policy.CRSParanoiaLevel,
			InboundThreshold:  policy.CRSInboundThreshold,
			OutboundThreshold: policy.CRSOutboundThreshold,
		}
	}
	if len(policy.DisabledPacks) > 0 {
		dto.DisabledPacks = append([]string(nil), policy.DisabledPacks...)
	}
	return dto
}

func responseSnapshotFromDTO(req *responsePolicyDTO) *control.ResponsePolicySnapshot {
	if req == nil {
		return nil
	}
	snap := &control.ResponsePolicySnapshot{
		Enabled:          req.Enabled,
		Mode:             control.NormalizePolicyValue(req.Mode),
		InspectHeaders:   req.InspectHeaders,
		InspectBody:      req.InspectBody,
		BodyLimit:        req.BodyLimit,
		HardCap:          req.HardCap,
		Decompress:       req.Decompress,
		ContentTypes:     append([]string(nil), req.ContentTypes...),
		MaxInflightBytes: req.MaxInflightBytes,
	}
	if req.DLP != nil {
		snap.DLP = &control.DLPPolicySnapshot{
			Enabled:           req.DLP.Enabled,
			Action:            control.NormalizePolicyValue(req.DLP.Action),
			DetectPAN:         req.DLP.DetectPAN,
			DetectSecrets:     req.DLP.DetectSecrets,
			DetectJWT:         req.DLP.DetectJWT,
			DetectPrivateKeys: req.DLP.DetectPrivateKeys,
			Redaction:         req.DLP.Redaction,
			MaxScanBytes:      req.DLP.MaxScanBytes,
		}
	}
	return snap
}

func responseDTOFromSnapshot(snap *control.ResponsePolicySnapshot) *responsePolicyDTO {
	if snap == nil {
		return nil
	}
	dto := &responsePolicyDTO{
		Enabled:          snap.Enabled,
		Mode:             snap.Mode,
		InspectHeaders:   snap.InspectHeaders,
		InspectBody:      snap.InspectBody,
		BodyLimit:        snap.BodyLimit,
		HardCap:          snap.HardCap,
		Decompress:       snap.Decompress,
		ContentTypes:     append([]string(nil), snap.ContentTypes...),
		MaxInflightBytes: snap.MaxInflightBytes,
	}
	if snap.DLP != nil {
		dto.DLP = &dlpPolicyDTO{
			Enabled:           snap.DLP.Enabled,
			Action:            snap.DLP.Action,
			DetectPAN:         snap.DLP.DetectPAN,
			DetectSecrets:     snap.DLP.DetectSecrets,
			DetectJWT:         snap.DLP.DetectJWT,
			DetectPrivateKeys: snap.DLP.DetectPrivateKeys,
			Redaction:         snap.DLP.Redaction,
			MaxScanBytes:      snap.DLP.MaxScanBytes,
		}
	}
	return dto
}

// decodeJSONBody rejects oversized payloads and trailing JSON garbage.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("request body must contain a single JSON object")
	}
	return nil
}
