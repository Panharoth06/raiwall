package control

import "github.com/Panharoth06/raiwall/internal/core/waf"

// ResolveWAFPolicyFor layers the per-site detection policy over the global
// policy. Empty values inherit; unknown app IDs resolve to the global policy.
func (s *ConfigSnapshot) ResolveWAFPolicyFor(appID string) WAFPolicySnapshot {
	var resolved WAFPolicySnapshot
	if s == nil {
		return resolved
	}
	if s.WAFPolicy != nil {
		resolved = cloneWAFPolicy(s.WAFPolicy)
	}
	if appID == "" {
		return resolved
	}
	app, ok := s.Apps[appID]
	if !ok || app == nil || app.WAFPolicy == nil {
		return resolved
	}
	overlayWAFPolicy(&resolved, app.WAFPolicy)
	return resolved
}

// DetectionModeFor returns the normalized effective detection mode for an app.
// An empty string (or "inherit") means the caller should fall back to the
// application/run mode.
func (s *ConfigSnapshot) DetectionModeFor(appID string) string {
	mode := NormalizePolicyValue(s.ResolveWAFPolicyFor(appID).DetectionMode)
	switch mode {
	case DetectionModeOff, DetectionModeAlert, DetectionModeBlock:
		return mode
	default:
		return ""
	}
}

// SensitivityFor returns the effective sensitivity preset for an app, or an
// empty string when no preset is configured.
func (s *ConfigSnapshot) SensitivityFor(appID string) string {
	sensitivity := NormalizePolicyValue(s.ResolveWAFPolicyFor(appID).Sensitivity)
	switch sensitivity {
	case waf.SensitivityLow, waf.SensitivityMedium, waf.SensitivityHigh:
		return sensitivity
	default:
		return ""
	}
}

func cloneWAFPolicy(p *WAFPolicySnapshot) WAFPolicySnapshot {
	if p == nil {
		return WAFPolicySnapshot{}
	}
	out := *p
	out.DetectionMode = NormalizePolicyValue(out.DetectionMode)
	out.Sensitivity = NormalizePolicyValue(out.Sensitivity)
	out.SemanticOverrides = cloneModuleModes(out.SemanticOverrides)
	out.DisabledPacks = append([]string(nil), out.DisabledPacks...)
	out.Response = cloneResponsePolicy(out.Response)
	return out
}

func overlayWAFPolicy(base, overlay *WAFPolicySnapshot) {
	if overlay == nil {
		return
	}
	if mode := NormalizePolicyValue(overlay.DetectionMode); mode != "" {
		base.DetectionMode = mode
	}
	if sensitivity := NormalizePolicyValue(overlay.Sensitivity); sensitivity != "" {
		base.Sensitivity = sensitivity
	}
	if len(overlay.SemanticOverrides) > 0 {
		if base.SemanticOverrides == nil {
			base.SemanticOverrides = make(map[waf.Module]waf.ModuleMode, len(overlay.SemanticOverrides))
		}
		for module, mode := range overlay.SemanticOverrides {
			base.SemanticOverrides[module] = mode
		}
	}
	if overlay.CRSEnabled != nil {
		enabled := *overlay.CRSEnabled
		base.CRSEnabled = &enabled
	}
	if overlay.CRSParanoiaLevel > 0 {
		base.CRSParanoiaLevel = overlay.CRSParanoiaLevel
	}
	if overlay.CRSInboundThreshold > 0 {
		base.CRSInboundThreshold = overlay.CRSInboundThreshold
	}
	if overlay.CRSOutboundThreshold > 0 {
		base.CRSOutboundThreshold = overlay.CRSOutboundThreshold
	}
	if len(overlay.DisabledPacks) > 0 {
		base.DisabledPacks = append([]string(nil), overlay.DisabledPacks...)
	}
	if overlay.Response != nil {
		if base.Response == nil {
			base.Response = &ResponsePolicySnapshot{}
		}
		overlayResponsePolicy(base.Response, overlay.Response)
	}
}

func cloneModuleModes(in map[waf.Module]waf.ModuleMode) map[waf.Module]waf.ModuleMode {
	if len(in) == 0 {
		return nil
	}
	out := make(map[waf.Module]waf.ModuleMode, len(in))
	for module, mode := range in {
		out[module] = mode
	}
	return out
}
