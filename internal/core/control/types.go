package control

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// RunMode represents the WAF and gateway operational protection mode.
type RunMode string

const (
	ModeDefense RunMode = "defense"
	ModeAudit   RunMode = "audit"
	ModeOffline RunMode = "offline"
)

// ParseRunMode parses and validates a run mode string.
func ParseRunMode(s string) (RunMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeDefense):
		return ModeDefense, nil
	case string(ModeAudit):
		return ModeAudit, nil
	case string(ModeOffline):
		return ModeOffline, nil
	default:
		return "", fmt.Errorf("invalid run mode: %q (expected 'defense', 'audit', or 'offline')", s)
	}
}

// IsValid checks if the run mode is one of the supported modes.
func (m RunMode) IsValid() bool {
	switch m {
	case ModeDefense, ModeAudit, ModeOffline:
		return true
	default:
		return false
	}
}

// UpstreamTarget defines a backend destination server.
type UpstreamTarget struct {
	Dial                string        `json:"dial"`
	Weight              int           `json:"weight,omitempty"`
	MaxFails            int           `json:"max_fails,omitempty"`
	FailTimeout         time.Duration `json:"fail_timeout,omitempty"`
	HealthCheckPath     string        `json:"health_check_path,omitempty"`
	HealthCheckInterval time.Duration `json:"health_check_interval,omitempty"`
}

// UnmarshalJSON custom unmarshaler for UpstreamTarget supporting string durations and numeric nanoseconds.
func (u *UpstreamTarget) UnmarshalJSON(data []byte) error {
	type rawTarget struct {
		Dial                string `json:"dial"`
		Weight              int    `json:"weight,omitempty"`
		MaxFails            int    `json:"max_fails,omitempty"`
		FailTimeout         any    `json:"fail_timeout,omitempty"`
		HealthCheckPath     string `json:"health_check_path,omitempty"`
		HealthCheckInterval any    `json:"health_check_interval,omitempty"`
		Interval            any    `json:"interval,omitempty"`
	}

	var raw rawTarget
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	u.Dial = raw.Dial
	u.Weight = raw.Weight
	u.MaxFails = raw.MaxFails
	u.HealthCheckPath = raw.HealthCheckPath

	parseDur := func(v any) (time.Duration, error) {
		if v == nil {
			return 0, nil
		}
		switch val := v.(type) {
		case string:
			if val == "" {
				return 0, nil
			}
			return time.ParseDuration(val)
		case float64:
			return time.Duration(val), nil
		case int64:
			return time.Duration(val), nil
		case int:
			return time.Duration(val), nil
		default:
			return 0, fmt.Errorf("unexpected duration type: %T", v)
		}
	}

	if raw.FailTimeout != nil {
		d, err := parseDur(raw.FailTimeout)
		if err != nil {
			return fmt.Errorf("invalid fail_timeout: %w", err)
		}
		u.FailTimeout = d
	}

	hcInt := raw.HealthCheckInterval
	if hcInt == nil {
		hcInt = raw.Interval
	}
	if hcInt != nil {
		d, err := parseDur(hcInt)
		if err != nil {
			return fmt.Errorf("invalid health_check_interval: %w", err)
		}
		u.HealthCheckInterval = d
	}

	return nil
}

// MarshalJSON serializes UpstreamTarget with string durations.
func (u UpstreamTarget) MarshalJSON() ([]byte, error) {
	type targetAlias struct {
		Dial                string `json:"dial"`
		Weight              int    `json:"weight,omitempty"`
		MaxFails            int    `json:"max_fails,omitempty"`
		FailTimeout         string `json:"fail_timeout,omitempty"`
		HealthCheckPath     string `json:"health_check_path,omitempty"`
		HealthCheckInterval string `json:"health_check_interval,omitempty"`
		Interval            string `json:"interval,omitempty"`
	}

	t := targetAlias{
		Dial:            u.Dial,
		Weight:          u.Weight,
		MaxFails:        u.MaxFails,
		HealthCheckPath: u.HealthCheckPath,
	}
	if u.FailTimeout > 0 {
		t.FailTimeout = u.FailTimeout.String()
	}
	if u.HealthCheckInterval > 0 {
		t.HealthCheckInterval = u.HealthCheckInterval.String()
		t.Interval = u.HealthCheckInterval.String()
	}
	return json.Marshal(t)
}

// ForwardingRule defines a path-prefix routing rule to custom upstream backends.
type ForwardingRule struct {
	ID                 string           `json:"id"`
	AppID              string           `json:"app_id,omitempty"`
	Prefix             string           `json:"prefix"`
	Upstreams          []UpstreamTarget `json:"upstreams"`
	StripPrefix        bool             `json:"strip_prefix"`
	HostHeaderOverride string           `json:"host_header_override,omitempty"`
	Comment            string           `json:"comment,omitempty"`
	IsActive           bool             `json:"is_active"`
}

// ProxySettings configures granular per-site reverse proxy parameters.
type ProxySettings struct {
	ClientIPSource    string `json:"client_ip_source,omitempty"`
	RewriteXFF        bool   `json:"rewrite_xff,omitempty"`
	HSTS              bool   `json:"hsts,omitempty"`
	EnableSSE         bool   `json:"enable_sse,omitempty"`
	EnableCompression bool   `json:"enable_compression,omitempty"`
	EnableIPv6        bool   `json:"enable_ipv6,omitempty"`
	RedirectHTTP      bool   `json:"redirect_http,omitempty"`
}

// AppConfig represents configuration for a protected application domain.
type AppConfig struct {
	ID                  string                        `json:"id"`
	Name                string                        `json:"name"`
	Hostnames           []string                      `json:"hostnames"`
	Mode                RunMode                       `json:"mode"`
	Upstreams           []UpstreamTarget              `json:"upstreams"`
	ForwardingRules     []ForwardingRule              `json:"forwarding_rules,omitempty"`
	ProxySettings       *ProxySettings                `json:"proxy_settings,omitempty"`
	SemanticPolicy      map[waf.Module]waf.ModuleMode `json:"semantic_policy,omitempty"`
	BlockStatusCode     int                           `json:"block_status_code,omitempty"`
	BlockResponseBody   string                        `json:"block_response_body,omitempty"`
	OfflineStatusCode   int                           `json:"offline_status_code,omitempty"`
	OfflineResponseBody string                        `json:"offline_response_body,omitempty"`
	CustomHeaders       map[string]string             `json:"custom_headers,omitempty"`
	// AuthEnabled turns on the per-site zero-trust gate: unauthenticated
	// browsers receive HTTP 467 with the branded login portal; API
	// transports (Bearer / JSON / /api/*) bypass transparently.
	AuthEnabled bool `json:"auth_enabled,omitempty"`
	// AuthBypassPaths lists path prefixes served without clearance.
	AuthBypassPaths []string `json:"auth_bypass_paths,omitempty"`
}

// RatePolicySnapshot holds compiled rate limiting configuration for a host or global (*).
type RatePolicySnapshot struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	Host                string        `json:"host"`
	Tier1Rate           int64         `json:"tier1_rate"`
	Tier1Burst          int64         `json:"tier1_burst"`
	Tier1Period         time.Duration `json:"tier1_period"`
	Tier2Threshold      int64         `json:"tier2_threshold"`
	Tier2Period         time.Duration `json:"tier2_period"`
	Tier2BanDuration    time.Duration `json:"tier2_ban_duration"`
	Tier3Threshold      int64         `json:"tier3_threshold"`
	Tier3BanDuration    time.Duration `json:"tier3_ban_duration"`
	WaitingRoomEnabled  bool          `json:"waiting_room_enabled"`
	WaitingRoomCapacity int64         `json:"waiting_room_capacity"`
	WaitingRoomPaths    []string      `json:"waiting_room_paths,omitempty"`
}

// BotConfigSnapshot holds bot mitigation configuration for a host or global (*).
type BotConfigSnapshot struct {
	ID            string   `json:"id"`
	Host          string   `json:"host"`
	PowEnabled    bool     `json:"pow_enabled"`
	PowDifficulty int      `json:"pow_difficulty"`
	TrapURLs      []string `json:"trap_urls"`
}

// ConfigSnapshot is an immutable snapshot of gateway configurations.
type ConfigSnapshot struct {
	Version          uint64                        `json:"version"`
	CreatedAt        time.Time                     `json:"created_at"`
	DefaultMode      RunMode                       `json:"default_mode"`
	Apps             map[string]*AppConfig         `json:"apps"`
	Exceptions       []*acl.ExceptionRule          `json:"exceptions,omitempty"`
	ACLRules         []*acl.ACLRule                `json:"acl_rules,omitempty"`
	RatePolicies     []*RatePolicySnapshot         `json:"rate_policies,omitempty"`
	BotConfigs       []*BotConfigSnapshot          `json:"bot_configs,omitempty"`
	SemanticDefaults map[waf.Module]waf.ModuleMode `json:"semantic_defaults,omitempty"`
	// InnerRulesDisabled holds virtual-patch (inner rule) signatures switched
	// off at runtime; every bundled rule is enabled unless listed here.
	InnerRulesDisabled map[string]struct{} `json:"inner_rules_disabled,omitempty"`
	// AppAuthSessionSecret signs the per-site clearance cookie (sl_jwt_session)
	// for zero-trust HTTP 467 gates; unified SSO across authorized sites.
	AppAuthSessionSecret string `json:"app_auth_session_secret,omitempty"`

	hostToAppID map[string]string
}

// NewConfigSnapshot initializes a new ConfigSnapshot and builds hostname lookups.
func NewConfigSnapshot(version uint64, defaultMode RunMode, apps []*AppConfig) *ConfigSnapshot {
	if !defaultMode.IsValid() {
		defaultMode = ModeDefense
	}

	snap := &ConfigSnapshot{
		Version:     version,
		CreatedAt:   time.Now().UTC(),
		DefaultMode: defaultMode,
		Apps:        make(map[string]*AppConfig, len(apps)),
		hostToAppID: make(map[string]string),
	}

	for _, app := range apps {
		if app == nil {
			continue
		}
		snap.Apps[app.ID] = app
		for _, host := range app.Hostnames {
			cleanHost := strings.ToLower(strings.TrimSpace(host))
			if h, _, err := net.SplitHostPort(cleanHost); err == nil {
				cleanHost = h
			}
			cleanHost = strings.Trim(cleanHost, "[]")
			if cleanHost != "" {
				snap.hostToAppID[cleanHost] = app.ID
			}
		}
	}

	return snap
}

// RebuildIndex rebuilds internal lookup indexes.
func (s *ConfigSnapshot) RebuildIndex() {
	if s == nil {
		return
	}
	s.hostToAppID = make(map[string]string)
	for _, app := range s.Apps {
		if app == nil {
			continue
		}
		for _, host := range app.Hostnames {
			cleanHost := strings.ToLower(strings.TrimSpace(host))
			if h, _, err := net.SplitHostPort(cleanHost); err == nil {
				cleanHost = h
			}
			cleanHost = strings.Trim(cleanHost, "[]")
			if cleanHost != "" {
				s.hostToAppID[cleanHost] = app.ID
			}
		}
	}
}

// GetAppForHost resolves an AppConfig by incoming Host header.
func (s *ConfigSnapshot) GetAppForHost(host string) (*AppConfig, bool) {
	if s == nil {
		return nil, false
	}
	cleanHost := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}
	cleanHost = strings.Trim(cleanHost, "[]")

	if s.hostToAppID == nil {
		s.RebuildIndex()
	}

	if appID, ok := s.hostToAppID[cleanHost]; ok {
		if app, found := s.Apps[appID]; found {
			return app, true
		}
	}
	return nil, false
}

// SemanticMatrixFor resolves the effective SemanticMatrix for an application,
// layering per-app overrides on top of the global defaults.
// Missing entries revert to the production defaults (Balance).
// An empty appID resolves the global defaults alone.
func (s *ConfigSnapshot) SemanticMatrixFor(appID string) waf.SemanticMatrix {
	if s == nil {
		return waf.DefaultMatrix()
	}

	base := waf.DefaultMatrix().ApplyOverrides(s.SemanticDefaults)
	if appID == "" {
		return base
	}
	if app, ok := s.Apps[appID]; ok && app != nil && len(app.SemanticPolicy) > 0 {
		return base.ApplyOverrides(app.SemanticPolicy)
	}
	return base
}

// GetRatePolicyForHost resolves a RatePolicySnapshot matching the incoming Host header, or falls back to wildcard (*).
func (s *ConfigSnapshot) GetRatePolicyForHost(host string) (*RatePolicySnapshot, bool) {
	if s == nil || len(s.RatePolicies) == 0 {
		return nil, false
	}
	cleanHost := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}
	cleanHost = strings.Trim(cleanHost, "[]")

	var wildcard *RatePolicySnapshot
	for _, rp := range s.RatePolicies {
		if rp == nil {
			continue
		}
		polHost := strings.ToLower(strings.TrimSpace(rp.Host))
		if polHost == cleanHost {
			return rp, true
		}
		if polHost == "*" || polHost == "" {
			wildcard = rp
		}
	}
	if wildcard != nil {
		return wildcard, true
	}
	return nil, false
}
