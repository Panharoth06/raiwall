package control

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
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
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Hostnames           []string          `json:"hostnames"`
	Mode                RunMode           `json:"mode"`
	Upstreams           []UpstreamTarget  `json:"upstreams"`
	ForwardingRules     []ForwardingRule  `json:"forwarding_rules,omitempty"`
	ProxySettings       *ProxySettings    `json:"proxy_settings,omitempty"`
	BlockStatusCode     int               `json:"block_status_code,omitempty"`
	BlockResponseBody   string            `json:"block_response_body,omitempty"`
	OfflineStatusCode   int               `json:"offline_status_code,omitempty"`
	OfflineResponseBody string            `json:"offline_response_body,omitempty"`
	CustomHeaders       map[string]string `json:"custom_headers,omitempty"`
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
	Version      uint64                `json:"version"`
	CreatedAt    time.Time             `json:"created_at"`
	DefaultMode  RunMode               `json:"default_mode"`
	Apps         map[string]*AppConfig `json:"apps"`
	Exceptions   []*acl.ExceptionRule  `json:"exceptions,omitempty"`
	ACLRules     []*acl.ACLRule        `json:"acl_rules,omitempty"`
	RatePolicies []*RatePolicySnapshot `json:"rate_policies,omitempty"`
	BotConfigs   []*BotConfigSnapshot  `json:"bot_configs,omitempty"`

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
