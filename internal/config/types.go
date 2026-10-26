package config

// File is the root of a Raiwall configuration document.
//
// The same document is consumed by the binary (--config raiwall.yaml), mounted
// by Docker Compose (./config/raiwall.yaml), and rendered by the Helm chart
// from values.yaml. It is the single source of truth for process, gateway, and
// declarative resource configuration.
type File struct {
	Version int `yaml:"version" json:"version"`

	Server  Server  `yaml:"server" json:"server"`
	Caddy   Caddy   `yaml:"caddy" json:"caddy"`
	Logging Logging `yaml:"logging" json:"logging"`

	Storage  Storage  `yaml:"storage" json:"storage"`
	Control  Control  `yaml:"control" json:"control"`
	Security Security `yaml:"security" json:"security"`

	WAF         WAF          `yaml:"waf" json:"waf"`
	Bot         Bot          `yaml:"bot" json:"bot"`
	RateLimit   *RateLimit   `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	WaitingRoom *WaitingRoom `yaml:"waiting_room,omitempty" json:"waiting_room,omitempty"`
	Auth        *Auth        `yaml:"auth,omitempty" json:"auth,omitempty"`
	Telemetry   *Telemetry   `yaml:"telemetry,omitempty" json:"telemetry,omitempty"`
	Sidecar     *Sidecar     `yaml:"sidecar,omitempty" json:"sidecar,omitempty"`

	// ThreatFeeds maps a feed name to a local file with one CIDR per line.
	ThreatFeeds map[string]string `yaml:"threat_feeds,omitempty" json:"threat_feeds,omitempty"`
	GeoIP       GeoIP             `yaml:"geoip" json:"geoip"`

	Declarative Declarative `yaml:"declarative" json:"declarative"`

	Applications      []Application      `yaml:"applications,omitempty" json:"applications,omitempty"`
	Certificates      []Certificate      `yaml:"certificates,omitempty" json:"certificates,omitempty"`
	ACLs              []ACLRule          `yaml:"acls,omitempty" json:"acls,omitempty"`
	Exceptions        []Exception        `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
	IPGroups          []IPGroup          `yaml:"ip_groups,omitempty" json:"ip_groups,omitempty"`
	RatePolicies      []RatePolicy       `yaml:"rate_policies,omitempty" json:"rate_policies,omitempty"`
	BotPolicies       []BotPolicy        `yaml:"bot_policies,omitempty" json:"bot_policies,omitempty"`
	IdentityProviders []IdentityProvider `yaml:"identity_providers,omitempty" json:"identity_providers,omitempty"`
	Templates         []Template         `yaml:"templates,omitempty" json:"templates,omitempty"`
	Detector          *Detector          `yaml:"detector,omitempty" json:"detector,omitempty"`
}

// Server configures the HTTP/HTTPS listeners owned by the gateway.
type Server struct {
	HTTP  HTTPListener  `yaml:"http" json:"http"`
	HTTPS HTTPSListener `yaml:"https" json:"https"`
	// AutoHTTPS enables Caddy's automatic HTTPS (redirects + ACME issuance).
	// Raiwall's managed certificate provider is used regardless; enable this
	// only when Caddy should also obtain certificates for unknown SNI.
	AutoHTTPS bool `yaml:"auto_https" json:"auto_https"`
	ACME      ACME `yaml:"acme" json:"acme"`
}

// HTTPListener configures the plaintext listener.
type HTTPListener struct {
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Listen  string `yaml:"listen" json:"listen"`
}

// HTTPSListener configures the TLS listener.
type HTTPSListener struct {
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Listen  string `yaml:"listen" json:"listen"`
	HTTP3   bool   `yaml:"http3" json:"http3"`
	// TLSMinVersion accepts "1.2" or "1.3".
	TLSMinVersion string `yaml:"tls_min_version" json:"tls_min_version"`
}

// ACME configures Let's Encrypt / ZeroSSL issuance when AutoHTTPS is enabled.
type ACME struct {
	Email   string `yaml:"email" json:"email"`
	CA      string `yaml:"ca" json:"ca"`
	Staging bool   `yaml:"staging" json:"staging"`
}

// Caddy configures the embedded Caddy runtime.
type Caddy struct {
	Admin   CaddyAdmin   `yaml:"admin" json:"admin"`
	Storage CaddyStorage `yaml:"storage" json:"storage"`
}

// CaddyAdmin configures the Caddy admin endpoint. "off" disables it.
type CaddyAdmin struct {
	Listen string `yaml:"listen" json:"listen"`
}

// CaddyStorage configures the certificate/key storage backend.
type CaddyStorage struct {
	Module string `yaml:"module" json:"module"`
	Root   string `yaml:"root" json:"root"`
}

// Logging configures Caddy's structured logs.
type Logging struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
	Output string `yaml:"output" json:"output"`
}

// Storage declares named database stores and binds the control/telemetry roles.
type Storage struct {
	// DatabaseURL is a convenience shortcut for a single store shared by both
	// roles. Do not use together with Stores.
	DatabaseURL string           `yaml:"database_url" json:"database_url"`
	Stores      map[string]Store `yaml:"stores" json:"stores"`
	Control     string           `yaml:"control" json:"control"`
	Telemetry   string           `yaml:"telemetry" json:"telemetry"`

	synthesizedFromDSN bool
}

// Store is a single named database store definition.
type Store struct {
	Driver        string   `yaml:"driver" json:"driver"`
	DSN           string   `yaml:"dsn" json:"dsn"`
	MaxOpen       int      `yaml:"max_open" json:"max_open"`
	MaxIdle       int      `yaml:"max_idle" json:"max_idle"`
	Retention     Duration `yaml:"retention" json:"retention"`
	PruneInterval Duration `yaml:"prune_interval" json:"prune_interval"`
}

// Control configures the control-plane database role and bootstrap operator.
type Control struct {
	HMACSecret string `yaml:"hmac_secret" json:"hmac_secret"`
	// DBPath is a legacy single-store override retained for migration. Prefer
	// Storage.DatabaseURL or Storage.Stores.
	DBPath         string         `yaml:"db_path,omitempty" json:"db_path,omitempty"`
	BootstrapAdmin BootstrapAdmin `yaml:"bootstrap_admin" json:"bootstrap_admin"`
}

// BootstrapAdmin creates the first operator account when the store is empty.
// When Password is empty a cryptographically random password is generated and
// logged once at WARN level.
type BootstrapAdmin struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Role     string `yaml:"role" json:"role"`
}

// Security controls strictness of the configuration loader.
type Security struct {
	// StrictSecrets rejects inline plaintext secrets instead of warning.
	StrictSecrets bool `yaml:"strict_secrets" json:"strict_secrets"`
}

// WAF configures the semantic inspection pipeline.
type WAF struct {
	Mode                string   `yaml:"mode" json:"mode"`
	BlockStatusCode     int      `yaml:"block_status_code" json:"block_status_code"`
	BlockResponseBody   string   `yaml:"block_response_body" json:"block_response_body"`
	OfflineStatusCode   int      `yaml:"offline_status_code" json:"offline_status_code"`
	OfflineResponseBody string   `yaml:"offline_response_body" json:"offline_response_body"`
	StripHeaders        []string `yaml:"strip_headers" json:"strip_headers"`
	ASTTimeout          Duration `yaml:"ast_timeout" json:"ast_timeout"`
	MaxParamSize        int      `yaml:"max_param_size" json:"max_param_size"`
}

// Bot configures bot mitigation and stateless proof-of-work.
type Bot struct {
	Defense       string   `yaml:"defense" json:"defense"`
	PoWDifficulty int64    `yaml:"pow_difficulty" json:"pow_difficulty"`
	PoWSecret     string   `yaml:"pow_secret" json:"pow_secret"`
	ClearanceTTL  Duration `yaml:"clearance_ttl" json:"clearance_ttl"`
	HoneypotTrap  *bool    `yaml:"honeypot_trap,omitempty" json:"honeypot_trap,omitempty"`
}

// RateLimit configures the three-tier rate limiter.
type RateLimit struct {
	Tier1Rate        int64    `yaml:"tier1_rate" json:"tier1_rate"`
	Tier1Period      Duration `yaml:"tier1_period" json:"tier1_period"`
	Tier1Burst       int64    `yaml:"tier1_burst" json:"tier1_burst"`
	Tier2Threshold   int64    `yaml:"tier2_threshold" json:"tier2_threshold"`
	Tier2Window      Duration `yaml:"tier2_window" json:"tier2_window"`
	Tier2BanDuration Duration `yaml:"tier2_ban_duration" json:"tier2_ban_duration"`
	Tier3Threshold   int64    `yaml:"tier3_threshold" json:"tier3_threshold"`
	Tier3Window      Duration `yaml:"tier3_window" json:"tier3_window"`
	Tier3BanDuration Duration `yaml:"tier3_ban_duration" json:"tier3_ban_duration"`
	Storage          string   `yaml:"storage" json:"storage"`
	StorageAddr      string   `yaml:"storage_addr" json:"storage_addr"`
}

// WaitingRoom configures the bounded admission queue.
type WaitingRoom struct {
	Enabled               *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxConcurrentInFlight int64    `yaml:"max_concurrent" json:"max_concurrent"`
	MaxQueueDepth         int64    `yaml:"max_queue_depth" json:"max_queue_depth"`
	AdmissionRate         int64    `yaml:"admission_rate" json:"admission_rate"`
	AdmissionTokenTTL     Duration `yaml:"token_ttl" json:"token_ttl"`
	TargetPaths           []string `yaml:"target_paths" json:"target_paths"`
}

// Auth configures the portal-wide zero-trust gate.
type Auth struct {
	Provider      string     `yaml:"provider" json:"provider"`
	IssuerURL     string     `yaml:"issuer_url" json:"issuer_url"`
	ClientID      string     `yaml:"client_id" json:"client_id"`
	ClientSecret  string     `yaml:"client_secret" json:"client_secret"`
	RedirectURL   string     `yaml:"redirect_url" json:"redirect_url"`
	Scopes        []string   `yaml:"scopes" json:"scopes"`
	Users         []AuthUser `yaml:"users" json:"users"`
	SessionSecret string     `yaml:"session_secret" json:"session_secret"`
	SessionCookie string     `yaml:"session_cookie" json:"session_cookie"`
	SessionTTL    Duration   `yaml:"session_ttl" json:"session_ttl"`
	SessionSecure *bool      `yaml:"session_secure,omitempty" json:"session_secure,omitempty"`
	BypassPaths   []string   `yaml:"bypass_paths" json:"bypass_paths"`
}

// AuthUser is a local portal account. Password (plaintext) is hashed at boot;
// PasswordHash accepts a pre-computed bcrypt hash.
type AuthUser struct {
	Username     string   `yaml:"username" json:"username"`
	Password     string   `yaml:"password" json:"password"`
	PasswordHash string   `yaml:"password_hash" json:"password_hash"`
	Email        string   `yaml:"email" json:"email"`
	Name         string   `yaml:"name" json:"name"`
	Roles        []string `yaml:"roles" json:"roles"`
}

// Telemetry configures forensic storage, batching, and alerting.
type Telemetry struct {
	FlushInterval Duration       `yaml:"flush_interval" json:"flush_interval"`
	BufferSize    int            `yaml:"buffer_size" json:"buffer_size"`
	Retention     Duration       `yaml:"retention" json:"retention"`
	AlertChannels []AlertChannel `yaml:"alert_channels" json:"alert_channels"`
}

// AlertChannel configures a Shoutrrr-compatible notification target.
type AlertChannel struct {
	Name     string   `yaml:"name" json:"name"`
	URL      string   `yaml:"url" json:"url"`
	Events   []string `yaml:"events" json:"events"`
	Cooldown Duration `yaml:"cooldown" json:"cooldown"`
}

// Sidecar configures the Envoy ext_proc gRPC service.
type Sidecar struct {
	Enabled     *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Listen      string `yaml:"listen" json:"listen"`
	MaxBodySize int64  `yaml:"max_body_size" json:"max_body_size"`
}

// GeoIP points at MaxMind database files used by ACL expressions.
type GeoIP struct {
	Country string `yaml:"country" json:"country"`
	ASN     string `yaml:"asn" json:"asn"`
}

// Declarative controls how file-declared resources are synced into the store.
type Declarative struct {
	// Mode is one of "off", "seed" (create missing only), or "sync" (upsert).
	Mode string `yaml:"mode" json:"mode"`
	// Prune removes file-managed records that are no longer declared.
	Prune bool `yaml:"prune" json:"prune"`
	// Strict aborts startup on conflicts with UI-managed records or invalid
	// resources. When false, invalid resources are skipped with a warning.
	Strict bool `yaml:"strict" json:"strict"`
}

// DeclarativeResources is the resolved resource bundle handed to the sync
// engine. It is nil when declarative mode is off.
type DeclarativeResources struct {
	Mode   string `json:"mode,omitempty"`
	Prune  bool   `json:"prune,omitempty"`
	Strict bool   `json:"strict,omitempty"`

	Applications      []Application      `json:"applications,omitempty"`
	Certificates      []Certificate      `json:"certificates,omitempty"`
	ACLs              []ACLRule          `json:"acls,omitempty"`
	Exceptions        []Exception        `json:"exceptions,omitempty"`
	IPGroups          []IPGroup          `json:"ip_groups,omitempty"`
	RatePolicies      []RatePolicy       `json:"rate_policies,omitempty"`
	BotPolicies       []BotPolicy        `json:"bot_policies,omitempty"`
	IdentityProviders []IdentityProvider `json:"identity_providers,omitempty"`
	Templates         []Template         `json:"templates,omitempty"`
	Detector          *Detector          `json:"detector,omitempty"`
}

// Resources returns the declarative bundle, or nil when sync is disabled.
func (f *File) Resources() *DeclarativeResources {
	if f.Declarative.Mode == "" || f.Declarative.Mode == "off" {
		return nil
	}
	return &DeclarativeResources{
		Mode:              f.Declarative.Mode,
		Prune:             f.Declarative.Prune,
		Strict:            f.Declarative.Strict,
		Applications:      f.Applications,
		Certificates:      f.Certificates,
		ACLs:              f.ACLs,
		Exceptions:        f.Exceptions,
		IPGroups:          f.IPGroups,
		RatePolicies:      f.RatePolicies,
		BotPolicies:       f.BotPolicies,
		IdentityProviders: f.IdentityProviders,
		Templates:         f.Templates,
		Detector:          f.Detector,
	}
}
