package caddy

import (
	"sync"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/grpc"
	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/alerts"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// MaxInspectionBodySize is the maximum body size buffered for threat inspection (1 MB).
const MaxInspectionBodySize = 1024 * 1024

// RateLimitSettings configures three-tiered rate limiting policies.
type RateLimitSettings struct {
	Tier1Rate        int64          `json:"tier1_rate,omitempty"`
	Tier1Period      caddy.Duration `json:"tier1_period,omitempty"`
	Tier1Burst       int64          `json:"tier1_burst,omitempty"`
	Tier2Threshold   int64          `json:"tier2_threshold,omitempty"`
	Tier2Window      caddy.Duration `json:"tier2_window,omitempty"`
	Tier2BanDuration caddy.Duration `json:"tier2_ban_duration,omitempty"`
	Tier3Threshold   int64          `json:"tier3_threshold,omitempty"`
	Tier3Window      caddy.Duration `json:"tier3_window,omitempty"`
	Tier3BanDuration caddy.Duration `json:"tier3_ban_duration,omitempty"`
	StorageType      string         `json:"storage_type,omitempty"`
	StorageAddr      string         `json:"storage_addr,omitempty"`
}

// WaitingRoomSettings configures the bounded virtual waiting room.
type WaitingRoomSettings struct {
	Enabled               bool           `json:"enabled,omitempty"`
	MaxConcurrentInFlight int64          `json:"max_concurrent,omitempty"`
	MaxQueueDepth         int64          `json:"max_queue_depth,omitempty"`
	AdmissionRate         int64          `json:"admission_rate,omitempty"`
	AdmissionTokenTTL     caddy.Duration `json:"admission_token_ttl,omitempty"`
	TargetPaths           []string       `json:"target_paths,omitempty"`
}

// ExceptionSettings holds parameter-level exception rules for false-positive suppression.
type ExceptionSettings struct {
	Rules []*acl.ExceptionRule `json:"rules,omitempty"`
}

// ACLSettings holds ACL rules, threat feeds, and GeoIP paths.
type ACLSettings struct {
	ThreatFeeds  map[string]string `json:"threat_feeds,omitempty"`
	GeoIPCountry string            `json:"geoip_country,omitempty"`
	GeoIPASN     string            `json:"geoip_asn,omitempty"`
	Rules        []*acl.ACLRule    `json:"rules,omitempty"`
}

// AuthSettings holds Pre-App Authentication Gateway configuration.
type AuthSettings struct {
	Provider      string            `json:"provider,omitempty"`
	IssuerURL     string            `json:"issuer_url,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
	ClientSecret  string            `json:"client_secret,omitempty"`
	RedirectURL   string            `json:"redirect_url,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	Users         []auth.SimpleUser `json:"users,omitempty"`
	SessionSecret string            `json:"session_secret,omitempty"`
	SessionCookie string            `json:"session_cookie,omitempty"`
	SessionTTL    caddy.Duration    `json:"session_ttl,omitempty"`
	SessionSecure *bool             `json:"session_secure,omitempty"`
	BypassPaths   []string          `json:"bypass_paths,omitempty"`
}

// AlertChannelSettings configures a notification channel in Caddyfile.
type AlertChannelSettings struct {
	Name     string         `json:"name,omitempty"`
	URL      string         `json:"url,omitempty"`
	Events   []string       `json:"events,omitempty"`
	Cooldown caddy.Duration `json:"cooldown,omitempty"`
}

// TelemetrySettings configures storage, ring buffer, and alerting for telemetry.
type TelemetrySettings struct {
	StorageType   string                 `json:"storage_type,omitempty"`
	StoragePath   string                 `json:"storage_path,omitempty"`
	FlushInterval caddy.Duration         `json:"flush_interval,omitempty"`
	BufferSize    int                    `json:"buffer_size,omitempty"`
	Retention     caddy.Duration         `json:"retention,omitempty"`
	AlertChannels []AlertChannelSettings `json:"alert_channels,omitempty"`
}

// StorageStoreSettings defines a single named store definition.
type StorageStoreSettings struct {
	Driver        string         `json:"driver,omitempty"`
	DSN           string         `json:"dsn,omitempty"`
	MaxOpen       int            `json:"max_open,omitempty"`
	MaxIdle       int            `json:"max_idle,omitempty"`
	Retention     caddy.Duration `json:"retention,omitempty"`
	PruneInterval caddy.Duration `json:"prune_interval,omitempty"`
}

// StorageSettings configures named stores and role bindings.
type StorageSettings struct {
	Stores    map[string]StorageStoreSettings `json:"stores,omitempty"`
	Control   string                          `json:"control,omitempty"`
	Telemetry string                          `json:"telemetry,omitempty"`
}

// ControlSettings configures the Control Plane database and management API.
type ControlSettings struct {
	DBPath     string `json:"db_path,omitempty"`
	HMACSecret string `json:"hmac_secret,omitempty"`
}

// SidecarSettings configures the Envoy ext_proc gRPC sidecar service.
type SidecarSettings struct {
	Listen      string `json:"listen,omitempty"`
	MaxBodySize int64  `json:"max_body_size,omitempty"`
}

// Middleware is the Caddy HTTP handler implementing Raiwall WAF and Gateway interception.
type Middleware struct {
	Mode                string         `json:"mode,omitempty"`
	BlockStatusCode     int            `json:"block_status_code,omitempty"`
	BlockResponseBody   string         `json:"block_response_body,omitempty"`
	OfflineStatusCode   int            `json:"offline_status_code,omitempty"`
	OfflineResponseBody string         `json:"offline_response_body,omitempty"`
	StripHeaders        []string       `json:"strip_headers,omitempty"`
	ASTTimeout          caddy.Duration `json:"ast_timeout,omitempty"`
	MaxParamSize        int            `json:"max_param_size,omitempty"`

	// Domain 3: Bot Mitigation & Chaos Engine configuration
	BotDefense    string         `json:"bot_defense,omitempty"`
	PoWDifficulty int64          `json:"pow_difficulty,omitempty"`
	ClearanceTTL  caddy.Duration `json:"clearance_ttl,omitempty"`
	HoneypotTrap  *bool          `json:"honeypot_trap,omitempty"`
	PoWSecret     string         `json:"pow_secret,omitempty"`

	// Domain 4: DDoS, HTTP Flood & Rate Limiting configuration
	RateLimitConfig   *RateLimitSettings   `json:"rate_limit,omitempty"`
	WaitingRoomConfig *WaitingRoomSettings `json:"waiting_room,omitempty"`

	// Domain 5: Access Control & Zero-Trust Identity Gateway
	ExceptionConfig *ExceptionSettings `json:"exceptions,omitempty"`
	ACLConfig       *ACLSettings       `json:"acl,omitempty"`
	AuthConfig      *AuthSettings      `json:"auth,omitempty"`

	// Domain 6: Observability, Forensics & Real-Time Alerting
	TelemetryConfig *TelemetrySettings `json:"telemetry,omitempty"`

	// Domain 7: Control Plane & Sidecar Mode
	StorageConfig *StorageSettings `json:"storage,omitempty"`
	ControlConfig *ControlSettings `json:"control,omitempty"`
	SidecarConfig *SidecarSettings `json:"sidecar,omitempty"`

	engine     waf.WAFEnginePort
	logger     *zap.Logger
	bufferPool *sync.Pool
	runMode    control.RunMode

	botClassifier *bot.BotClassifier
	routeClass    *bot.RouteClassifier
	powEngine     *bot.PoWEngine
	clearanceMgr  *bot.ClearanceManager
	honeypotInj   *bot.HoneypotInjector
	trapCtrl      *bot.TrapController

	banManager   *rate.BanManager
	tier1Limiter *rate.Tier1VelocityLimiter
	tier2Limiter *rate.Tier2AttackLimiter
	tier3Trap    *rate.Tier3ScannerTrap
	waitingRoom  *rate.WaitingRoomManager
	rateStorage  rate.RateStorage

	exceptionEngine *acl.ExceptionEngine
	bartTable       *acl.BARTTable
	ipGroupMgr      *acl.IPGroupManager
	geoIPReader     acl.GeoIPReader
	aclEngine       *acl.ACLEngine
	authGateway     *auth.AuthGateway
	appAuthGate     *auth.AppAuthGate
	// appAuthGateMu guards the cached gate across concurrent pipeline
	// requests; appAuthGateSecret tracks the snapshot secret the gate was
	// built with so rotations invalidate prior clearance cookies.
	appAuthGateMu     sync.Mutex
	appAuthGateSecret string
	appAuthSecretOnce sync.Once

	storageRegistry    *storage.Registry
	telemetryStore     telemetry.ForensicStore
	ringBuffer         *telemetry.RingBuffer
	streamer           *api.EventStreamer
	alertEngine        *alerts.AlertEngine
	metrics            *telemetry.Metrics
	telemetryAPI       *api.TelemetryAPI
	uiHandler          *UIHandler
	controlStore       control.ControlStore
	controlAPI         *api.Server
	templateManager    *templates.TemplateManager
	sidecarServer      *grpc.ExtProcServer
	upstreamRegistry   *UpstreamRegistry
	discoveryCataloger *APIDiscoveryCataloger
}

var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddy.CleanerUpper          = (*Middleware)(nil)
)
