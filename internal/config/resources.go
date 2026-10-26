package config

// Application declares a protected application (protected site) and how traffic
// for its hostnames is routed.
type Application struct {
	Name        string   `yaml:"name" json:"name"`
	Hostnames   []string `yaml:"hostnames" json:"hostnames"`
	Mode        string   `yaml:"mode" json:"mode"`
	Description string   `yaml:"description" json:"description"`

	RoutingType    string     `yaml:"routing_type" json:"routing_type"`
	DocumentRoot   string     `yaml:"document_root" json:"document_root"`
	RedirectURL    string     `yaml:"redirect_url" json:"redirect_url"`
	RedirectStatus int        `yaml:"redirect_status" json:"redirect_status"`
	Upstreams      []Upstream `yaml:"upstreams" json:"upstreams"`
	LoadBalancing  string     `yaml:"load_balancing" json:"load_balancing"`

	SSLMode     string `yaml:"ssl_mode" json:"ssl_mode"`
	Certificate string `yaml:"certificate" json:"certificate"`

	Ports         []Port            `yaml:"ports" json:"ports"`
	Proxy         *AppProxy         `yaml:"proxy" json:"proxy"`
	CustomHeaders map[string]string `yaml:"custom_headers" json:"custom_headers"`
	Auth          *AppAuth          `yaml:"auth" json:"auth"`
	Forwarding    []ForwardingRule  `yaml:"forwarding" json:"forwarding"`
	Semantic      map[string]string `yaml:"semantic_policy" json:"semantic_policy"`

	BlockStatusCode     int    `yaml:"block_status_code" json:"block_status_code"`
	BlockResponseBody   string `yaml:"block_response_body" json:"block_response_body"`
	OfflineStatusCode   int    `yaml:"offline_status_code" json:"offline_status_code"`
	OfflineResponseBody string `yaml:"offline_response_body" json:"offline_response_body"`
}

// Upstream is a load-balanced backend target.
type Upstream struct {
	Dial                string   `yaml:"dial" json:"dial"`
	Weight              int      `yaml:"weight" json:"weight"`
	MaxFails            int      `yaml:"max_fails" json:"max_fails"`
	FailTimeout         Duration `yaml:"fail_timeout" json:"fail_timeout"`
	HealthCheckPath     string   `yaml:"health_check_path" json:"health_check_path"`
	HealthCheckInterval Duration `yaml:"health_check_interval" json:"health_check_interval"`
}

// Port is declarative listener metadata for an application.
type Port struct {
	Port   int    `yaml:"port" json:"port"`
	Scheme string `yaml:"scheme" json:"scheme"`
}

// AppProxy configures per-application reverse proxy behavior.
type AppProxy struct {
	ClientIPSource    string `yaml:"client_ip_source" json:"client_ip_source"`
	RewriteXFF        bool   `yaml:"rewrite_xff" json:"rewrite_xff"`
	HSTS              bool   `yaml:"hsts" json:"hsts"`
	EnableSSE         bool   `yaml:"enable_sse" json:"enable_sse"`
	EnableCompression bool   `yaml:"enable_compression" json:"enable_compression"`
	EnableIPv6        bool   `yaml:"enable_ipv6" json:"enable_ipv6"`
	RedirectHTTP      bool   `yaml:"redirect_http" json:"redirect_http"`
}

// AppAuth enables the per-site zero-trust gate.
type AppAuth struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	BypassPaths []string `yaml:"bypass_paths" json:"bypass_paths"`
}

// ForwardingRule routes a path prefix to alternate upstreams.
type ForwardingRule struct {
	Prefix             string     `yaml:"prefix" json:"prefix"`
	Upstreams          []Upstream `yaml:"upstreams" json:"upstreams"`
	StripPrefix        bool       `yaml:"strip_prefix" json:"strip_prefix"`
	HostHeaderOverride string     `yaml:"host_header_override" json:"host_header_override"`
	Comment            string     `yaml:"comment" json:"comment"`
}

// Certificate declares a managed TLS certificate. Private key material should
// be supplied through ${ENV} interpolation or a mounted file.
type Certificate struct {
	Name        string   `yaml:"name" json:"name"`
	Domains     []string `yaml:"domains" json:"domains"`
	Source      string   `yaml:"source" json:"source"`
	CertPEM     string   `yaml:"cert_pem" json:"cert_pem"`
	KeyPEM      string   `yaml:"key_pem" json:"key_pem"`
	AutoRenew   bool     `yaml:"auto_renew" json:"auto_renew"`
	ACMEStaging bool     `yaml:"acme_staging" json:"acme_staging"`
}

// ACLRule declares a compiled boolean access control rule.
type ACLRule struct {
	Name        string `yaml:"name" json:"name"`
	Expression  string `yaml:"expression" json:"expression"`
	Action      string `yaml:"action" json:"action"`
	Priority    int64  `yaml:"priority" json:"priority"`
	StatusCode  int64  `yaml:"status_code" json:"status_code"`
	RedirectURL string `yaml:"redirect_url" json:"redirect_url"`
	Enabled     *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// Exception declares a parameter-level false-positive bypass.
type Exception struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Host        string `yaml:"host" json:"host"`
	Path        string `yaml:"path" json:"path"`
	PathPrefix  string `yaml:"path_prefix" json:"path_prefix"`
	PathRegex   string `yaml:"path_regex" json:"path_regex"`
	Method      string `yaml:"method" json:"method"`
	Location    string `yaml:"location" json:"location"`
	ParamName   string `yaml:"param_name" json:"param_name"`
	ParamRegex  string `yaml:"param_regex" json:"param_regex"`
	RuleID      string `yaml:"rule_id" json:"rule_id"`
	Enabled     *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// IPGroup declares a named CIDR collection.
type IPGroup struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description" json:"description"`
	Entries     []IPGroupEntry `yaml:"entries" json:"entries"`
}

// IPGroupEntry is one CIDR prefix inside an IP group.
type IPGroupEntry struct {
	CIDR    string `yaml:"cidr" json:"cidr"`
	Comment string `yaml:"comment" json:"comment"`
}

// RatePolicy declares per-host tiered rate limiting.
type RatePolicy struct {
	Name                string   `yaml:"name" json:"name"`
	Host                string   `yaml:"host" json:"host"`
	Tier1Rate           int64    `yaml:"tier1_rate" json:"tier1_rate"`
	Tier1Burst          int64    `yaml:"tier1_burst" json:"tier1_burst"`
	Tier1Period         Duration `yaml:"tier1_period" json:"tier1_period"`
	Tier2Threshold      int64    `yaml:"tier2_threshold" json:"tier2_threshold"`
	Tier2Window         Duration `yaml:"tier2_window" json:"tier2_window"`
	Tier2BanDuration    Duration `yaml:"tier2_ban_duration" json:"tier2_ban_duration"`
	Tier3Threshold      int64    `yaml:"tier3_threshold" json:"tier3_threshold"`
	Tier3Window         Duration `yaml:"tier3_window" json:"tier3_window"`
	Tier3BanDuration    Duration `yaml:"tier3_ban_duration" json:"tier3_ban_duration"`
	WaitingRoomEnabled  bool     `yaml:"waiting_room_enabled" json:"waiting_room_enabled"`
	WaitingRoomCapacity int64    `yaml:"waiting_room_capacity" json:"waiting_room_capacity"`
	WaitingRoomPaths    []string `yaml:"waiting_room_paths" json:"waiting_room_paths"`
}

// BotPolicy declares per-host bot mitigation overrides.
type BotPolicy struct {
	Name          string   `yaml:"name" json:"name"`
	Host          string   `yaml:"host" json:"host"`
	PoWEnabled    bool     `yaml:"pow_enabled" json:"pow_enabled"`
	PoWDifficulty int64    `yaml:"pow_difficulty" json:"pow_difficulty"`
	TrapURLs      []string `yaml:"trap_urls" json:"trap_urls"`
}

// IdentityProvider declares an external identity connector (oidc|ldap|github).
type IdentityProvider struct {
	Name    string         `yaml:"name" json:"name"`
	Type    string         `yaml:"type" json:"type"`
	Enabled *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Config  map[string]any `yaml:"config" json:"config"`
}

// Template declares a deterministic response page.
type Template struct {
	Name        string `yaml:"name" json:"name"`
	StatusCode  int    `yaml:"status_code" json:"status_code"`
	Title       string `yaml:"title" json:"title"`
	ContentHTML string `yaml:"content_html" json:"content_html"`
	CustomCSS   string `yaml:"custom_css" json:"custom_css"`
	BrandName   string `yaml:"brand_name" json:"brand_name"`
	LogoURL     string `yaml:"logo_url" json:"logo_url"`
}

// Detector declares semantic module modes and disabled virtual patches.
type Detector struct {
	Modules            map[string]string `yaml:"modules" json:"modules"`
	InnerRulesDisabled []string          `yaml:"inner_rules_disabled" json:"inner_rules_disabled"`
}
