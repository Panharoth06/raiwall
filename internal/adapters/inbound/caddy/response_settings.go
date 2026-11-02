package caddy

import (
	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/response"
)

// ResponseSettings is the process-level outbound inspection configuration.
// Pointer fields preserve the difference between "not set" and "explicitly
// false" so per-site policies can inherit cleanly.
type ResponseSettings struct {
	Enabled          *bool          `json:"enabled,omitempty"`
	Mode             string         `json:"mode,omitempty"`
	InspectHeaders   *bool          `json:"inspect_headers,omitempty"`
	InspectBody      *bool          `json:"inspect_body,omitempty"`
	BodyLimit        int            `json:"body_limit,omitempty"`
	HardCap          int            `json:"hard_cap,omitempty"`
	Decompress       *bool          `json:"decompress,omitempty"`
	ContentTypes     []string       `json:"content_types,omitempty"`
	MaxInflightBytes int64          `json:"max_inflight_bytes,omitempty"`
	DLP              *DLPSettings   `json:"dlp,omitempty"`
}

// DLPSettings is the process-level DLP configuration.
type DLPSettings struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	Action            string `json:"action,omitempty"`
	DetectPAN         *bool  `json:"detect_pan,omitempty"`
	DetectSecrets     *bool  `json:"detect_secrets,omitempty"`
	DetectJWT         *bool  `json:"detect_jwt,omitempty"`
	DetectPrivateKeys *bool  `json:"detect_private_keys,omitempty"`
	Redaction         string `json:"redaction,omitempty"`
	MaxScanBytes      int    `json:"max_scan_bytes,omitempty"`
}

func responseSettingsFromConfig(src config.Response) *ResponseSettings {
	settings := &ResponseSettings{
		Enabled:          src.Enabled,
		Mode:             src.Mode,
		InspectHeaders:   src.InspectHeaders,
		InspectBody:      src.InspectBody,
		BodyLimit:        src.BodyLimit,
		HardCap:          src.HardCap,
		Decompress:       src.Decompress,
		ContentTypes:     append([]string(nil), src.ContentTypes...),
		MaxInflightBytes: src.MaxInflightBytes,
	}
	if src.DLP != nil {
		settings.DLP = &DLPSettings{
			Enabled:           src.DLP.Enabled,
			Action:            src.DLP.Action,
			DetectPAN:         src.DLP.DetectPAN,
			DetectSecrets:     src.DLP.DetectSecrets,
			DetectJWT:         src.DLP.DetectJWT,
			DetectPrivateKeys: src.DLP.DetectPrivateKeys,
			Redaction:         src.DLP.Redaction,
			MaxScanBytes:      src.DLP.MaxScanBytes,
		}
	}
	return settings
}

// responseConfigFor resolves the effective response and DLP configuration for an app.
func (m *Middleware) responseConfigFor(snap *control.ConfigSnapshot, appID string) response.Config {
	conf := response.Config{
		Enabled:          false,
		Mode:             control.ResponseModeAudit,
		InspectHeaders:   true,
		InspectBody:      true,
		BodyLimit:        control.DefaultResponseBodyLimit,
		HardCap:          control.DefaultResponseHardCap,
		Decompress:       true,
		ContentTypes:     control.DefaultContentTypes(),
		MaxInflightBytes: control.DefaultResponseMaxInflight,
		DLP: response.DLPConfig{
			Enabled:           true,
			Action:            control.ResponseModeAudit,
			DetectPAN:         true,
			DetectSecrets:     true,
			DetectJWT:         true,
			DetectPrivateKeys: true,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      control.DefaultDLPMaxScanBytes,
		},
	}

	if m.ResponseConfig != nil {
		if m.ResponseConfig.Enabled != nil {
			conf.Enabled = *m.ResponseConfig.Enabled
		}
		if m.ResponseConfig.Mode != "" {
			conf.Mode = m.ResponseConfig.Mode
		}
		if m.ResponseConfig.InspectHeaders != nil {
			conf.InspectHeaders = *m.ResponseConfig.InspectHeaders
		}
		if m.ResponseConfig.InspectBody != nil {
			conf.InspectBody = *m.ResponseConfig.InspectBody
		}
		if m.ResponseConfig.BodyLimit > 0 {
			conf.BodyLimit = m.ResponseConfig.BodyLimit
		}
		if m.ResponseConfig.HardCap > 0 {
			conf.HardCap = m.ResponseConfig.HardCap
		}
		if m.ResponseConfig.Decompress != nil {
			conf.Decompress = *m.ResponseConfig.Decompress
		}
		if len(m.ResponseConfig.ContentTypes) > 0 {
			conf.ContentTypes = append([]string(nil), m.ResponseConfig.ContentTypes...)
		}
		if m.ResponseConfig.MaxInflightBytes > 0 {
			conf.MaxInflightBytes = m.ResponseConfig.MaxInflightBytes
		}
		if m.ResponseConfig.DLP != nil {
			dlp := m.ResponseConfig.DLP
			if dlp.Enabled != nil {
				conf.DLP.Enabled = *dlp.Enabled
			}
			if dlp.Action != "" {
				conf.DLP.Action = dlp.Action
			}
			if dlp.DetectPAN != nil {
				conf.DLP.DetectPAN = *dlp.DetectPAN
			}
			if dlp.DetectSecrets != nil {
				conf.DLP.DetectSecrets = *dlp.DetectSecrets
			}
			if dlp.DetectJWT != nil {
				conf.DLP.DetectJWT = *dlp.DetectJWT
			}
			if dlp.DetectPrivateKeys != nil {
				conf.DLP.DetectPrivateKeys = *dlp.DetectPrivateKeys
			}
			if dlp.Redaction != "" {
				conf.DLP.Redaction = dlp.Redaction
			}
			if dlp.MaxScanBytes > 0 {
				conf.DLP.MaxScanBytes = dlp.MaxScanBytes
			}
		}
	}

	if snap != nil {
		policy := snap.ResolveWAFPolicyFor(appID)
		if policy.Response != nil {
			r := policy.Response
			if r.Enabled != nil {
				conf.Enabled = *r.Enabled
			}
			if r.Mode != "" {
				conf.Mode = r.Mode
			}
			if r.InspectHeaders != nil {
				conf.InspectHeaders = *r.InspectHeaders
			}
			if r.InspectBody != nil {
				conf.InspectBody = *r.InspectBody
			}
			if r.BodyLimit > 0 {
				conf.BodyLimit = r.BodyLimit
			}
			if r.HardCap > 0 {
				conf.HardCap = r.HardCap
			}
			if r.Decompress != nil {
				conf.Decompress = *r.Decompress
			}
			if len(r.ContentTypes) > 0 {
				conf.ContentTypes = append([]string(nil), r.ContentTypes...)
			}
			if r.MaxInflightBytes > 0 {
				conf.MaxInflightBytes = r.MaxInflightBytes
			}
			if r.DLP != nil {
				dlp := r.DLP
				if dlp.Enabled != nil {
					conf.DLP.Enabled = *dlp.Enabled
				}
				if dlp.Action != "" {
					conf.DLP.Action = dlp.Action
				}
				if dlp.DetectPAN != nil {
					conf.DLP.DetectPAN = *dlp.DetectPAN
				}
				if dlp.DetectSecrets != nil {
					conf.DLP.DetectSecrets = *dlp.DetectSecrets
				}
				if dlp.DetectJWT != nil {
					conf.DLP.DetectJWT = *dlp.DetectJWT
				}
				if dlp.DetectPrivateKeys != nil {
					conf.DLP.DetectPrivateKeys = *dlp.DetectPrivateKeys
				}
				if dlp.Redaction != "" {
					conf.DLP.Redaction = dlp.Redaction
				}
				if dlp.MaxScanBytes > 0 {
					conf.DLP.MaxScanBytes = dlp.MaxScanBytes
				}
			}
		}
	}

	return conf
}

func (m *Middleware) dlpEngineFor(cfg response.Config) (*response.Engine, error) {
	fp := cfg.Fingerprint()
	if val, ok := m.dlpEngines.Load(fp); ok {
		return val.(*response.Engine), nil
	}
	eng, err := response.New(cfg)
	if err != nil {
		return nil, err
	}
	m.dlpEngines.Store(fp, eng)
	return eng, nil
}
