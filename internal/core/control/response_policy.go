package control

import (
	"fmt"
	"strings"
)

// Response inspection defaults. These are policy defaults, not runtime
// tuning: the data plane may lower the limits, but never raise the hard cap
// without an explicit operator override.
const (
	DefaultResponseBodyLimit      = 1024 * 1024 // inspect up to 1 MiB
	DefaultResponseHardCap        = 8 * 1024 * 1024
	DefaultResponseMaxInflight    = 64 * 1024 * 1024
	DefaultDLPMaxScanBytes        = 1024 * 1024
	ResponseModeAudit             = "audit"
	ResponseModeRedact            = "redact"
	ResponseModeBlock             = "block"
	ResponseModeInherit           = "inherit"
	ResponseInspectHeaderModeName = "headers"
)

// DefaultResponsePolicySnapshot returns a fresh snapshot with standard production defaults.
func DefaultResponsePolicySnapshot() *ResponsePolicySnapshot {
	enabled := false
	inspectHeaders := true
	inspectBody := true
	decompress := true
	dlpEnabled := true
	detectPAN := true
	detectSecrets := true
	detectJWT := true
	detectPrivateKeys := true
	return &ResponsePolicySnapshot{
		Enabled:          &enabled,
		Mode:             ResponseModeAudit,
		InspectHeaders:   &inspectHeaders,
		InspectBody:      &inspectBody,
		BodyLimit:        DefaultResponseBodyLimit,
		HardCap:          DefaultResponseHardCap,
		Decompress:       &decompress,
		ContentTypes:     DefaultContentTypes(),
		MaxInflightBytes: DefaultResponseMaxInflight,
		DLP: &DLPPolicySnapshot{
			Enabled:           &dlpEnabled,
			Action:            ResponseModeAudit,
			DetectPAN:         &detectPAN,
			DetectSecrets:     &detectSecrets,
			DetectJWT:         &detectJWT,
			DetectPrivateKeys: &detectPrivateKeys,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      DefaultDLPMaxScanBytes,
		},
	}
}

// ResponsePolicySnapshot is the global or per-site outbound inspection policy.
// Empty strings and zero values inherit from the enclosing scope. Pointer
// booleans distinguish "inherit" from an explicit false.
type ResponsePolicySnapshot struct {
	Enabled          *bool                `json:"enabled,omitempty"`
	Mode             string               `json:"mode,omitempty"`
	InspectHeaders   *bool                `json:"inspect_headers,omitempty"`
	InspectBody      *bool                `json:"inspect_body,omitempty"`
	BodyLimit        int                  `json:"body_limit,omitempty"`
	HardCap          int                  `json:"hard_cap,omitempty"`
	Decompress       *bool                `json:"decompress,omitempty"`
	ContentTypes     []string             `json:"content_types,omitempty"`
	MaxInflightBytes int64                `json:"max_inflight_bytes,omitempty"`
	DLP              *DLPPolicySnapshot   `json:"dlp,omitempty"`
}

// DLPPolicySnapshot configures data-loss-prevention detection on outbound
// headers and bodies. Action "inherit" follows the response mode.
type DLPPolicySnapshot struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	Action            string `json:"action,omitempty"`
	DetectPAN         *bool  `json:"detect_pan,omitempty"`
	DetectSecrets     *bool  `json:"detect_secrets,omitempty"`
	DetectJWT         *bool  `json:"detect_jwt,omitempty"`
	DetectPrivateKeys *bool  `json:"detect_private_keys,omitempty"`
	Redaction         string `json:"redaction,omitempty"`
	MaxScanBytes      int    `json:"max_scan_bytes,omitempty"`
}

// DefaultContentTypes is the body allowlist used when a policy does not
// specify one. Matching is by base MIME type.
func DefaultContentTypes() []string {
	return []string{
		"text/html",
		"text/plain",
		"text/xml",
		"application/xml",
		"application/json",
		"application/javascript",
		"text/javascript",
		"application/x-javascript",
	}
}

// IsValidResponseMode reports whether mode is a supported enforcement mode.
func IsValidResponseMode(mode string) bool {
	switch NormalizePolicyValue(mode) {
	case "", ResponseModeInherit, ResponseModeAudit, ResponseModeRedact, ResponseModeBlock:
		return true
	default:
		return false
	}
}

// NormalizeResponseMode maps empty and "inherit" to an empty string.
func NormalizeResponseMode(mode string) string {
	mode = NormalizePolicyValue(mode)
	if mode == ResponseModeInherit {
		return ""
	}
	return mode
}


func cloneResponsePolicy(p *ResponsePolicySnapshot) *ResponsePolicySnapshot {
	if p == nil {
		return nil
	}
	out := *p
	out.Enabled = cloneBoolPtr(p.Enabled)
	out.InspectHeaders = cloneBoolPtr(p.InspectHeaders)
	out.InspectBody = cloneBoolPtr(p.InspectBody)
	out.Decompress = cloneBoolPtr(p.Decompress)
	out.ContentTypes = append([]string(nil), p.ContentTypes...)
	if p.DLP != nil {
		dlp := *p.DLP
		dlp.Enabled = cloneBoolPtr(p.DLP.Enabled)
		dlp.DetectPAN = cloneBoolPtr(p.DLP.DetectPAN)
		dlp.DetectSecrets = cloneBoolPtr(p.DLP.DetectSecrets)
		dlp.DetectJWT = cloneBoolPtr(p.DLP.DetectJWT)
		dlp.DetectPrivateKeys = cloneBoolPtr(p.DLP.DetectPrivateKeys)
		out.DLP = &dlp
	}
	return &out
}

// OverlayResponsePolicy applies overlay fields onto base.
func OverlayResponsePolicy(base, overlay *ResponsePolicySnapshot) {
	if overlay == nil {
		return
	}
	if overlay.Enabled != nil {
		v := *overlay.Enabled
		base.Enabled = &v
	}
	if mode := NormalizeResponseMode(overlay.Mode); mode != "" {
		base.Mode = mode
	}
	if overlay.InspectHeaders != nil {
		v := *overlay.InspectHeaders
		base.InspectHeaders = &v
	}
	if overlay.InspectBody != nil {
		v := *overlay.InspectBody
		base.InspectBody = &v
	}
	if overlay.BodyLimit > 0 {
		base.BodyLimit = overlay.BodyLimit
	}
	if overlay.HardCap > 0 {
		base.HardCap = overlay.HardCap
	}
	if overlay.Decompress != nil {
		v := *overlay.Decompress
		base.Decompress = &v
	}
	if len(overlay.ContentTypes) > 0 {
		base.ContentTypes = append([]string(nil), overlay.ContentTypes...)
	}
	if overlay.MaxInflightBytes > 0 {
		base.MaxInflightBytes = overlay.MaxInflightBytes
	}
	if overlay.DLP != nil {
		if base.DLP == nil {
			base.DLP = &DLPPolicySnapshot{}
		}
		dlp := overlay.DLP
		if dlp.Enabled != nil {
			v := *dlp.Enabled
			base.DLP.Enabled = &v
		}
		if action := NormalizeResponseMode(dlp.Action); action != "" {
			base.DLP.Action = action
		}
		if dlp.DetectPAN != nil {
			v := *dlp.DetectPAN
			base.DLP.DetectPAN = &v
		}
		if dlp.DetectSecrets != nil {
			v := *dlp.DetectSecrets
			base.DLP.DetectSecrets = &v
		}
		if dlp.DetectJWT != nil {
			v := *dlp.DetectJWT
			base.DLP.DetectJWT = &v
		}
		if dlp.DetectPrivateKeys != nil {
			v := *dlp.DetectPrivateKeys
			base.DLP.DetectPrivateKeys = &v
		}
		if dlp.Redaction != "" {
			base.DLP.Redaction = dlp.Redaction
		}
		if dlp.MaxScanBytes > 0 {
			base.DLP.MaxScanBytes = dlp.MaxScanBytes
		}
	}
}

func overlayResponsePolicy(base, overlay *ResponsePolicySnapshot) {
	OverlayResponsePolicy(base, overlay)
}

// Fingerprint returns the canonical 15-field fingerprint identifying this response policy.
// Format: Enabled|Mode|InspectHeaders|InspectBody|BodyLimit|HardCap|Decompress|ContentTypes|DLPDetectPAN|DLPAction|DLPDetectSecrets|DLPDetectJWT|DLPDetectPrivateKeys|DLPRedaction|DLPMaxScanBytes
func (p *ResponsePolicySnapshot) Fingerprint() string {
	if p == nil {
		return "false||false|false|0|0|false||false||false|false|false||0"
	}
	enabled := false
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	mode := p.Mode
	inspectHeaders := true
	if p.InspectHeaders != nil {
		inspectHeaders = *p.InspectHeaders
	}
	inspectBody := true
	if p.InspectBody != nil {
		inspectBody = *p.InspectBody
	}
	bodyLimit := p.BodyLimit
	if bodyLimit <= 0 {
		bodyLimit = DefaultResponseBodyLimit
	}
	hardCap := p.HardCap
	if hardCap <= 0 {
		hardCap = DefaultResponseHardCap
	}
	decompress := true
	if p.Decompress != nil {
		decompress = *p.Decompress
	}
	contentTypes := p.ContentTypes
	if len(contentTypes) == 0 {
		contentTypes = DefaultContentTypes()
	}
	dlpPAN := false
	dlpAction := ""
	dlpSecrets := false
	dlpJWT := false
	dlpPrivateKeys := false
	dlpRedaction := "[REDACTED]"
	dlpMaxScanBytes := DefaultDLPMaxScanBytes
	if p.DLP != nil {
		if p.DLP.DetectPAN != nil {
			dlpPAN = *p.DLP.DetectPAN
		}
		dlpAction = p.DLP.Action
		if p.DLP.DetectSecrets != nil {
			dlpSecrets = *p.DLP.DetectSecrets
		}
		if p.DLP.DetectJWT != nil {
			dlpJWT = *p.DLP.DetectJWT
		}
		if p.DLP.DetectPrivateKeys != nil {
			dlpPrivateKeys = *p.DLP.DetectPrivateKeys
		}
		if p.DLP.Redaction != "" {
			dlpRedaction = p.DLP.Redaction
		}
		if p.DLP.MaxScanBytes > 0 {
			dlpMaxScanBytes = p.DLP.MaxScanBytes
		}
	}
	return fmt.Sprintf("%t|%s|%t|%t|%d|%d|%t|%s|%t|%s|%t|%t|%t|%s|%d",
		enabled, mode, inspectHeaders, inspectBody, bodyLimit, hardCap,
		decompress, strings.Join(contentTypes, ","),
		dlpPAN, dlpAction, dlpSecrets, dlpJWT, dlpPrivateKeys,
		dlpRedaction, dlpMaxScanBytes)
}

// NormalizeResponsePolicy cleans and standardizes a response policy snapshot.
func NormalizeResponsePolicy(p *ResponsePolicySnapshot) *ResponsePolicySnapshot {
	if p == nil {
		return nil
	}
	out := cloneResponsePolicy(p)
	out.Mode = NormalizePolicyValue(out.Mode)
	if out.DLP != nil {
		out.DLP.Action = NormalizePolicyValue(out.DLP.Action)
	}
	return out
}
