package control

import (
	"database/sql"
	"time"
)

// SiteApp represents a protected application domain in the control plane.
type SiteApp struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Hostnames           string    `json:"hostnames"`
	Mode                string    `json:"mode"`
	Upstreams           string    `json:"upstreams"`
	BlockStatusCode     int64     `json:"block_status_code"`
	BlockResponseBody   string    `json:"block_response_body"`
	OfflineStatusCode   int64     `json:"offline_status_code"`
	OfflineResponseBody string    `json:"offline_response_body"`
	CustomHeaders       string    `json:"custom_headers"`
	ProxySettings       string    `json:"proxy_settings"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ExceptionRule represents a parameter-level false-positive bypass exception.
type ExceptionRule struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Host        string    `json:"host"`
	PathRegex   string    `json:"path_regex"`
	PathPrefix  string    `json:"path_prefix"`
	Method      string    `json:"method"`
	Location    string    `json:"location"`
	ParamName   string    `json:"param_name"`
	ParamRegex  string    `json:"param_regex"`
	RuleID      string    `json:"rule_id"`
	IsActive    int64     `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AclRule represents a compiled boolean access control rule.
type AclRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Expression  string    `json:"expression"`
	Action      string    `json:"action"`
	Priority    int64     `json:"priority"`
	StatusCode  int64     `json:"status_code"`
	RedirectUrl string    `json:"redirect_url"`
	IsActive    int64     `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RatePolicy represents tiered rate limiting configuration.
type RatePolicy struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Host                string    `json:"host"`
	Tier1Rate           int64     `json:"tier1_rate"`
	Tier1Burst          int64     `json:"tier1_burst"`
	Tier1PeriodSec      int64     `json:"tier1_period_sec"`
	Tier2Threshold      int64     `json:"tier2_threshold"`
	Tier2PeriodSec      int64     `json:"tier2_period_sec"`
	Tier2BanDurationSec int64     `json:"tier2_ban_duration_sec"`
	Tier3Threshold      int64     `json:"tier3_threshold"`
	Tier3BanDurationSec int64     `json:"tier3_ban_duration_sec"`
	WaitingRoomEnabled  int64     `json:"waiting_room_enabled"`
	WaitingRoomCapacity int64     `json:"waiting_room_capacity"`
	WaitingRoomPaths    string    `json:"waiting_room_paths"`
	IsActive            int64     `json:"is_active"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// BotConfig represents active bot mitigation and challenge settings.
type BotConfig struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	PowEnabled    int64     `json:"pow_enabled"`
	PowDifficulty int64     `json:"pow_difficulty"`
	TrapUrls      string    `json:"trap_urls"`
	IsActive      int64     `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ConfigSnapshotRecord represents an immutable versioned snapshot record in persistent storage.
type ConfigSnapshotRecord struct {
	Version      int64     `json:"version"`
	SnapshotData string    `json:"snapshot_data"`
	Author       string    `json:"author"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
}

// UserRecord represents an administrative user with role-based access.
type UserRecord struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	IsActive     int64     `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ApiKeyRecord represents an API key authentication credential.
type ApiKeyRecord struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	KeyHash    string       `json:"key_hash"`
	Role       string       `json:"role"`
	ExpiresAt  sql.NullTime `json:"expires_at"`
	IsActive   int64        `json:"is_active"`
	CreatedAt  time.Time    `json:"created_at"`
	LastUsedAt sql.NullTime `json:"last_used_at"`
}

// ForwardingRuleRecord represents a path-prefix routing rule to custom backends.
type ForwardingRuleRecord struct {
	ID                 string    `json:"id"`
	AppID              string    `json:"app_id"`
	Prefix             string    `json:"prefix"`
	Upstreams          string    `json:"upstreams"`
	StripPrefix        int64     `json:"strip_prefix"`
	HostHeaderOverride string    `json:"host_header_override"`
	Comment            string    `json:"comment"`
	IsActive           int64     `json:"is_active"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ApiResourceRecord represents an automatically cataloged API endpoint.
type ApiResourceRecord struct {
	ID          string    `json:"id"`
	AppID       string    `json:"app_id"`
	Method      string    `json:"method"`
	PathPattern string    `json:"path_pattern"`
	ContentType string    `json:"content_type"`
	HitCount    int64     `json:"hit_count"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
}
