package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/pkg/acl"
)

// RunMode represents the WAF and gateway operational protection mode.
type RunMode string

const (
	// ModeDefense actively inspects and blocks malicious requests.
	ModeDefense RunMode = "defense"
	// ModeAudit passively inspects and logs security events without blocking.
	ModeAudit RunMode = "audit"
	// ModeOffline serves a static maintenance screen and halts upstream forwarding.
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
	// Dial is the address to connect to (e.g., "127.0.0.1:8080").
	Dial string `json:"dial"`
	// Weight is the selection weight for load balancing. Default 1.
	Weight int `json:"weight,omitempty"`
	// MaxFails is the number of consecutive failures before marking unhealthy.
	MaxFails int `json:"max_fails,omitempty"`
	// FailTimeout is how long the upstream remains unhealthy before retry.
	FailTimeout time.Duration `json:"fail_timeout,omitempty"`
	// HealthCheckPath is the HTTP path for active health probes.
	HealthCheckPath string `json:"health_check_path,omitempty"`
	// HealthCheckInterval is how frequently probes are executed.
	HealthCheckInterval time.Duration `json:"health_check_interval,omitempty"`
}

// AppConfig represents configuration for a protected application domain.
type AppConfig struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Hostnames           []string          `json:"hostnames"`
	Mode                RunMode           `json:"mode"`
	Upstreams           []UpstreamTarget  `json:"upstreams"`
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

	// hostToAppID maps normalized hostnames to App IDs for fast O(1) matching.
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

// RebuildIndex rebuilds internal lookup indexes (e.g. host to app ID).
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

// GetAppForHost resolves an AppConfig by incoming Host header (stripping port if present).
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

