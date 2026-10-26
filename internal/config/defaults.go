package config

import (
	"os"
	"strings"
	"time"
)

const (
	// MaxASTTimeout bounds AST verification so a crafted payload cannot pin a
	// CPU core (project hard constraint: 5 ms per parameter).
	MaxASTTimeout = 5 * time.Millisecond

	// MaxInspectionParamSize bounds the per-parameter inspection buffer
	// (project hard constraint: 32 KB).
	MaxInspectionParamSize = 32 * 1024
)

const (
	// DefaultConfigPath is the container path mounted by Compose and Helm.
	DefaultConfigPath = "/etc/raiwall/raiwall.yaml"

	defaultHTTPListen      = ":8080"
	defaultHTTPSListen     = ":8443"
	defaultControlDBPath   = "file:/var/lib/raiwall/raiwall_control.db?_pragma=busy_timeout(5000)"
	defaultCertmagicRoot   = "/var/lib/raiwall/certmagic"
	defaultTelemetryDSN    = "file:/var/lib/raiwall/raiwall_telemetry.db?_pragma=busy_timeout(5000)"
	defaultAdminUsername   = "admin"
	defaultAdminRole       = "admin"
	defaultASTTimeout      = 5 * time.Millisecond
	defaultMaxParamSize    = 32 * 1024
	defaultTelemetryRetain = 30 * 24 * time.Hour
	defaultSidecarListen   = ":50051"
	defaultSessionCookie   = "rw_session"
	defaultACLBlockStatus  = 403
	defaultACLRedirectCode = 302
)

// applyDefaults fills unset fields so a minimal document is deployable. All
// defaults are documented in docs/configuration.md and duplicated in the
// example config so operators can see every effective value.
func applyDefaults(f *File) {
	if f.Version == 0 {
		f.Version = 1
	}

	if f.Server.HTTP.Listen == "" {
		f.Server.HTTP.Listen = defaultHTTPListen
	}
	if f.Server.HTTP.Enabled == nil {
		f.Server.HTTP.Enabled = boolPtr(true)
	}
	if f.Server.HTTPS.Listen == "" {
		f.Server.HTTPS.Listen = defaultHTTPSListen
	}
	if f.Server.HTTPS.Enabled == nil {
		f.Server.HTTPS.Enabled = boolPtr(true)
	}
	if f.Server.HTTPS.TLSMinVersion == "" {
		f.Server.HTTPS.TLSMinVersion = "1.2"
	}

	if f.Caddy.Admin.Listen == "" {
		f.Caddy.Admin.Listen = "off"
	}
	if f.Caddy.Storage.Module == "" {
		f.Caddy.Storage.Module = "file_system"
	}
	if f.Caddy.Storage.Root == "" {
		f.Caddy.Storage.Root = defaultCertmagicRoot
	}

	if f.Logging.Level == "" {
		f.Logging.Level = "info"
	}
	if f.Logging.Format == "" {
		f.Logging.Format = "json"
	}
	if f.Logging.Output == "" {
		f.Logging.Output = "stderr"
	}

	applyStorageDefaults(&f.Storage, &f.Control)

	if f.Control.BootstrapAdmin.Username == "" {
		f.Control.BootstrapAdmin.Username = defaultAdminUsername
	}
	if f.Control.BootstrapAdmin.Role == "" {
		f.Control.BootstrapAdmin.Role = defaultAdminRole
	}

	if f.WAF.Mode == "" {
		f.WAF.Mode = "defense"
	}
	if f.WAF.BlockStatusCode == 0 {
		f.WAF.BlockStatusCode = 403
	}
	if f.WAF.OfflineStatusCode == 0 {
		f.WAF.OfflineStatusCode = 503
	}
	if f.WAF.ASTTimeout == 0 {
		f.WAF.ASTTimeout = Duration(defaultASTTimeout)
	}
	if f.WAF.MaxParamSize == 0 {
		f.WAF.MaxParamSize = defaultMaxParamSize
	}

	if f.Bot.Defense == "" {
		f.Bot.Defense = "defense"
	}
	if f.Bot.PoWDifficulty == 0 {
		f.Bot.PoWDifficulty = 50000
	}
	if f.Bot.ClearanceTTL == 0 {
		f.Bot.ClearanceTTL = Duration(2 * time.Hour)
	}
	if f.Bot.HoneypotTrap == nil {
		f.Bot.HoneypotTrap = boolPtr(true)
	}

	if f.Telemetry != nil && f.Telemetry.Retention == 0 {
		f.Telemetry.Retention = Duration(defaultTelemetryRetain)
	}

	if f.Auth != nil && f.Auth.SessionCookie == "" {
		f.Auth.SessionCookie = defaultSessionCookie
	}

	if f.Sidecar != nil && f.Sidecar.Listen == "" {
		f.Sidecar.Listen = defaultSidecarListen
	}

	if f.Declarative.Mode == "" {
		if f.hasDeclaredResources() {
			f.Declarative.Mode = "sync"
		} else {
			f.Declarative.Mode = "off"
		}
	}

	applyEnvOverrides(f)
	applyResourceDefaults(f)
}

func applyStorageDefaults(storage *Storage, control *Control) {
	if storage.DatabaseURL == "" && len(storage.Stores) == 0 && control.DBPath != "" {
		storage.DatabaseURL = control.DBPath
	}

	// Legacy deployments (and docker-compose < 0.2) used DATABASE_URL. It is
	// still honoured when no explicit storage block exists.
	if storage.DatabaseURL == "" && len(storage.Stores) == 0 {
		if legacy := strings.TrimSpace(os.Getenv("DATABASE_URL")); legacy != "" {
			storage.DatabaseURL = legacy
		}
	}

	if storage.DatabaseURL != "" && len(storage.Stores) == 0 {
		storage.Stores = map[string]Store{
			"default": {
				Driver:  driverFromDSN(storage.DatabaseURL),
				DSN:     storage.DatabaseURL,
				MaxOpen: 10,
				MaxIdle: 5,
			},
		}
		storage.Control = "default"
		storage.Telemetry = "default"
		storage.synthesizedFromDSN = true
	}

	if len(storage.Stores) == 0 {
		storage.Stores = map[string]Store{
			"control": {
				Driver:  "sqlite",
				DSN:     defaultControlDBPath,
				MaxOpen: 1,
				MaxIdle: 1,
			},
			"telemetry": {
				Driver:        "sqlite",
				DSN:           defaultTelemetryDSN,
				Retention:     Duration(defaultTelemetryRetain),
				PruneInterval: Duration(time.Hour),
			},
		}
		storage.Control = "control"
		storage.Telemetry = "telemetry"
	}

	if storage.Control == "" {
		storage.Control = firstStoreKey(storage.Stores)
	}
	if storage.Telemetry == "" {
		storage.Telemetry = storage.Control
	}
}

func applyResourceDefaults(f *File) {
	for i := range f.Applications {
		app := &f.Applications[i]
		if app.Mode == "" {
			app.Mode = f.WAF.Mode
		}
		if app.SSLMode == "" {
			app.SSLMode = "none"
		}
		if app.RoutingType == "" {
			app.RoutingType = "proxy"
		}
		if app.RedirectStatus == 0 {
			app.RedirectStatus = 302
		}
	}
	for i := range f.ACLs {
		rule := &f.ACLs[i]
		if rule.Action == "" {
			rule.Action = "block"
		}
		if rule.Action == "block" && rule.StatusCode == 0 {
			rule.StatusCode = defaultACLBlockStatus
		}
		if rule.Action == "redirect" && rule.StatusCode == 0 {
			rule.StatusCode = defaultACLRedirectCode
		}
	}
}

func (f *File) hasDeclaredResources() bool {
	return len(f.Applications) > 0 || len(f.Certificates) > 0 || len(f.ACLs) > 0 ||
		len(f.Exceptions) > 0 || len(f.IPGroups) > 0 || len(f.RatePolicies) > 0 ||
		len(f.BotPolicies) > 0 || len(f.IdentityProviders) > 0 || len(f.Templates) > 0 ||
		f.Detector != nil
}

func firstStoreKey(stores map[string]Store) string {
	// Prefer a stable, human-readable key when present.
	if _, ok := stores["default"]; ok {
		return "default"
	}
	if _, ok := stores["control"]; ok {
		return "control"
	}
	for name := range stores {
		return name
	}
	return ""
}

func driverFromDSN(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres"):
		return "postgres"
	case strings.HasPrefix(dsn, "file:"):
		return "sqlite"
	case dsn == "memory" || dsn == ":memory:":
		return "memory"
	default:
		return "postgres"
	}
}

func boolPtr(v bool) *bool { return &v }
