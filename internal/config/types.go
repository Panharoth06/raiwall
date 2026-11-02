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
	// ProxyProtocol accepts PROXY v1/v2 headers from trusted load balancers.
	ProxyProtocol *ProxyProtocol `yaml:"proxy_protocol,omitempty" json:"proxy_protocol,omitempty"`
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
	DBPath string `yaml:"db_path,omitempty" json:"db_path,omitempty"`
	// AutoApply commits and hot-swaps a new configuration snapshot after every
	// successful control-plane mutation. When disabled, operators stage changes
	// and commit them from the Deployments page.
	AutoApply      bool           `yaml:"auto_apply,omitempty" json:"auto_apply,omitempty"`
	BootstrapAdmin BootstrapAdmin `yaml:"bootstrap_admin" json:"bootstrap_admin"`
	// PublicURL is the canonical external base (scheme://host[:port]). It is
	// used for CSRF origin checks and console redirects.
	PublicURL string `yaml:"public_url" json:"public_url"`
	// AllowedNetworks restricts /.raiwall admin traffic to these CIDRs. An
	// empty list allows every source; the runbook recommends a VPN/IP allowlist.
	AllowedNetworks []string `yaml:"allowed_networks" json:"allowed_networks"`
	// Session controls dashboard operator sessions.
	Session Session `yaml:"session" json:"session"`
	// SnapshotRetention keeps at most this many configuration snapshots
	// (newest first plus the active version). 0 disables pruning. A pointer
	// distinguishes "unset" (apply the default) from an explicit 0.
	SnapshotRetention *int `yaml:"snapshot_retention" json:"snapshot_retention"`
	// AuditRetention prunes control-plane audit rows older than this. 0 keeps
	// them forever. A pointer distinguishes "unset" (apply the default) from an
	// explicit 0.
	AuditRetention *Duration `yaml:"audit_retention" json:"audit_retention"`
}

// Session configures opaque dashboard operator sessions.
type Session struct {
	// IdleTimeout ends a session after this much inactivity.
	IdleTimeout Duration `yaml:"idle_timeout" json:"idle_timeout"`
	// AbsoluteTimeout is a hard limit regardless of activity.
	AbsoluteTimeout Duration `yaml:"absolute_timeout" json:"absolute_timeout"`
	// Secure marks the cookie Secure and uses the __Host- prefix. Default true;
	// set false only for local plaintext development.
	Secure *bool `yaml:"secure,omitempty" json:"secure,omitempty"`
	// AllowBasicAuth keeps HTTP Basic authentication on API routes for tooling.
	// Disabled by default; the dashboard uses the login flow.
	AllowBasicAuth bool `yaml:"allow_basic_auth" json:"allow_basic_auth"`
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
	// ProductionMode refuses unsafe deployment defaults (weak admin password,
	// short or missing secrets, insecure cookies, non-TLS public URL, HTTPS
	// without a certificate source). Enable it in Compose/Helm/production.
	ProductionMode bool `yaml:"production_mode" json:"production_mode"`
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
	MaxParamSize        int       `yaml:"max_param_size" json:"max_param_size"`
	CRS                 CRS       `yaml:"crs" json:"crs"`
	Response            Response  `yaml:"response" json:"response"`
}

// Response configures outbound inspection and DLP. Nil booleans and zero
// values fall back to the policy defaults.
type Response struct {
	Enabled          *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Mode             string         `yaml:"mode" json:"mode"`
	InspectHeaders   *bool          `yaml:"inspect_headers,omitempty" json:"inspect_headers,omitempty"`
	InspectBody      *bool          `yaml:"inspect_body,omitempty" json:"inspect_body,omitempty"`
	BodyLimit        int            `yaml:"body_limit" json:"body_limit"`
	HardCap          int            `yaml:"hard_cap" json:"hard_cap"`
	Decompress       *bool          `yaml:"decompress,omitempty" json:"decompress,omitempty"`
	ContentTypes     []string       `yaml:"content_types,omitempty" json:"content_types,omitempty"`
	MaxInflightBytes int64          `yaml:"max_inflight_bytes" json:"max_inflight_bytes"`
	DLP              *DLP           `yaml:"dlp,omitempty" json:"dlp,omitempty"`
}

// DLP configures outbound data-loss prevention.
type DLP struct {
	Enabled           *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Action            string `yaml:"action" json:"action"`
	DetectPAN         *bool  `yaml:"detect_pan,omitempty" json:"detect_pan,omitempty"`
	DetectSecrets     *bool  `yaml:"detect_secrets,omitempty" json:"detect_secrets,omitempty"`
	DetectJWT         *bool  `yaml:"detect_jwt,omitempty" json:"detect_jwt,omitempty"`
	DetectPrivateKeys *bool  `yaml:"detect_private_keys,omitempty" json:"detect_private_keys,omitempty"`
	Redaction         string `yaml:"redaction,omitempty" json:"redaction,omitempty"`
	MaxScanBytes      int    `yaml:"max_scan_bytes" json:"max_scan_bytes"`
}

// CRS configures the optional OWASP Core Rule Set engine (Coraza).
type CRS struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	Mode              string `yaml:"mode" json:"mode"`
	ParanoiaLevel     int    `yaml:"paranoia_level" json:"paranoia_level"`
	InboundThreshold  int    `yaml:"inbound_threshold" json:"inbound_threshold"`
	OutboundThreshold int    `yaml:"outbound_threshold" json:"outbound_threshold"`
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

	// Redis cluster options. They apply when Storage is "redis": the same
	// connection carries rate limits, bans, and the HA event channel.
	RedisUsername              string `yaml:"redis_username" json:"redis_username"`
	RedisPassword              string `yaml:"redis_password" json:"redis_password"`
	RedisTLS                   bool   `yaml:"redis_tls" json:"redis_tls"`
	RedisTLSServerName         string `yaml:"redis_tls_server_name" json:"redis_tls_server_name"`
	RedisTLSCAFile             string `yaml:"redis_tls_ca_file" json:"redis_tls_ca_file"`
	RedisTLSInsecureSkipVerify bool   `yaml:"redis_tls_insecure_skip_verify" json:"redis_tls_insecure_skip_verify"`
	ClusterChannel             string `yaml:"cluster_channel" json:"cluster_channel"`
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
	// TrustedProxies lists hops in front of Envoy whose X-Forwarded-For
	// entries are skipped when locating the client address.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
}

// GeoIP points at MaxMind database files used by ACL expressions, telemetry
// enrichment and the geo maps in the dashboard.
type GeoIP struct {
	Country string `yaml:"country" json:"country"`
	City    string `yaml:"city" json:"city"`
	ASN     string `yaml:"asn" json:"asn"`
	// AutoUpdate downloads missing or stale databases on startup when
	// RAIWALL_GEOIP_LICENSE_KEY is present. The key is never persisted in the
	// configuration file so it cannot leak through the admin API.
	AutoUpdate bool `yaml:"auto_update" json:"auto_update"`
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
