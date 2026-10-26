package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ValidationError aggregates every problem found in a document so operators
// can fix the file in one pass instead of restart-looping.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	return fmt.Sprintf("%d configuration problems:\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

type validator struct {
	problems []string
}

func (v *validator) add(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

// Validate checks schema invariants that do not require the database.
func (f *File) Validate() error {
	v := &validator{}

	if f.Version != 1 {
		v.add("version must be 1 (got %d)", f.Version)
	}
	f.validateServer(v)
	f.validateLogging(v)
	f.validateStorage(v)
	f.validateControl(v)
	f.validateWAF(v)
	f.validateBot(v)
	f.validateRateLimit(v)
	f.validateTelemetry(v)
	f.validateDeclarative(v)
	f.validateResources(v)

	if len(v.problems) == 0 {
		return nil
	}
	sort.Strings(v.problems)
	return &ValidationError{Problems: v.problems}
}

func (f *File) validateServer(v *validator) {
	if enabled(f.Server.HTTP.Enabled) {
		if !validListen(f.Server.HTTP.Listen) {
			v.add("server.http.listen %q is not a valid address", f.Server.HTTP.Listen)
		}
	}
	if enabled(f.Server.HTTPS.Enabled) {
		if !validListen(f.Server.HTTPS.Listen) {
			v.add("server.https.listen %q is not a valid address", f.Server.HTTPS.Listen)
		}
	}
	if enabled(f.Server.HTTP.Enabled) && enabled(f.Server.HTTPS.Enabled) &&
		f.Server.HTTP.Listen == f.Server.HTTPS.Listen {
		v.add("server.http.listen and server.https.listen must differ")
	}
	if !enabled(f.Server.HTTP.Enabled) && !enabled(f.Server.HTTPS.Enabled) {
		v.add("at least one of server.http.enabled or server.https.enabled must be true")
	}
	if f.Server.HTTPS.TLSMinVersion != "1.2" && f.Server.HTTPS.TLSMinVersion != "1.3" {
		v.add("server.https.tls_min_version must be \"1.2\" or \"1.3\"")
	}
	if f.Caddy.Admin.Listen != "off" && !validListen(f.Caddy.Admin.Listen) {
		v.add("caddy.admin.listen %q must be \"off\" or a host:port address", f.Caddy.Admin.Listen)
	}
	if f.Caddy.Storage.Module != "file_system" {
		v.add("caddy.storage.module %q is unsupported (expected file_system)", f.Caddy.Storage.Module)
	}
}

func (f *File) validateLogging(v *validator) {
	switch f.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		v.add("logging.level %q must be debug, info, warn, or error", f.Logging.Level)
	}
	switch f.Logging.Format {
	case "json", "console":
	default:
		v.add("logging.format %q must be json or console", f.Logging.Format)
	}
	if f.Logging.Output == "" {
		v.add("logging.output must be stderr, stdout, or a file path")
	}
}

func (f *File) validateStorage(v *validator) {
	if f.Storage.DatabaseURL != "" && len(f.Storage.Stores) > 0 && !f.Storage.synthesizedFromDSN {
		v.add("storage.database_url and storage.stores are mutually exclusive")
	}
	if _, ok := f.Storage.Stores[f.Storage.Control]; !ok {
		v.add("storage.control references unknown store %q", f.Storage.Control)
	}
	if _, ok := f.Storage.Stores[f.Storage.Telemetry]; !ok {
		v.add("storage.telemetry references unknown store %q", f.Storage.Telemetry)
	}
	for name, store := range f.Storage.Stores {
		switch store.Driver {
		case "sqlite", "postgres", "clickhouse", "memory":
		default:
			v.add("storage.stores.%s.driver %q must be sqlite, postgres, clickhouse, or memory", name, store.Driver)
		}
		if store.DSN == "" && store.Driver != "memory" {
			v.add("storage.stores.%s.dsn is required", name)
		}
		if store.MaxOpen < 0 || store.MaxIdle < 0 {
			v.add("storage.stores.%s pool sizes must be non-negative", name)
		}
	}
}

func (f *File) validateControl(v *validator) {
	admin := f.Control.BootstrapAdmin
	if admin.Username == "" {
		v.add("control.bootstrap_admin.username is required")
	}
	if admin.Role != "admin" && admin.Role != "viewer" {
		v.add("control.bootstrap_admin.role must be admin or viewer")
	}
}

func (f *File) validateWAF(v *validator) {
	switch strings.ToLower(f.WAF.Mode) {
	case "defense", "audit", "offline":
	default:
		v.add("waf.mode %q must be defense, audit, or offline", f.WAF.Mode)
	}
	if !validStatus(f.WAF.BlockStatusCode) {
		v.add("waf.block_status_code %d must be between 200 and 599", f.WAF.BlockStatusCode)
	}
	if !validStatus(f.WAF.OfflineStatusCode) {
		v.add("waf.offline_status_code %d must be between 200 and 599", f.WAF.OfflineStatusCode)
	}
	ast := f.WAF.ASTTimeout.Std()
	if ast <= 0 || ast > MaxASTTimeout {
		v.add("waf.ast_timeout must be between 1ms and %s", MaxASTTimeout)
	}
	if f.WAF.MaxParamSize <= 0 || f.WAF.MaxParamSize > MaxInspectionParamSize {
		v.add("waf.max_param_size must be between 1 and %d bytes", MaxInspectionParamSize)
	}
}

func (f *File) validateBot(v *validator) {
	switch strings.ToLower(f.Bot.Defense) {
	case "defense", "challenge", "strict", "audit", "off", "disabled":
	default:
		v.add("bot.defense %q must be defense, challenge, strict, audit, or off", f.Bot.Defense)
	}
	if f.Bot.PoWDifficulty < 0 {
		v.add("bot.pow_difficulty must be non-negative")
	}
}

func (f *File) validateRateLimit(v *validator) {
	if f.RateLimit == nil {
		return
	}
	switch strings.ToLower(f.RateLimit.Storage) {
	case "", "memory", "redis":
	default:
		v.add("rate_limit.storage %q must be memory or redis", f.RateLimit.Storage)
	}
	if strings.EqualFold(f.RateLimit.Storage, "redis") && f.RateLimit.StorageAddr == "" {
		v.add("rate_limit.storage_addr is required when rate_limit.storage is redis")
	}
}

func (f *File) validateTelemetry(v *validator) {
	if f.Telemetry == nil {
		return
	}
	if f.Telemetry.BufferSize < 0 {
		v.add("telemetry.buffer_size must be non-negative")
	}
	for i, ch := range f.Telemetry.AlertChannels {
		if ch.Name == "" {
			v.add("telemetry.alert_channels[%d].name is required", i)
		}
		if ch.URL == "" {
			v.add("telemetry.alert_channels[%d].url is required", i)
		}
	}
}

func (f *File) validateDeclarative(v *validator) {
	switch f.Declarative.Mode {
	case "off", "seed", "sync":
	default:
		v.add("declarative.mode %q must be off, seed, or sync", f.Declarative.Mode)
	}
	if f.Declarative.Prune && f.Declarative.Mode != "sync" {
		v.add("declarative.prune requires declarative.mode: sync")
	}
}

func (f *File) validateResources(v *validator) {
	seenNames := map[string]bool{}
	seenHosts := map[string]string{}

	for i, app := range f.Applications {
		prefix := fmt.Sprintf("applications[%d]", i)
		if !validName(app.Name) {
			v.add("%s.name %q must be a slug (letters, digits, '-', '_', '.')", prefix, app.Name)
		} else if seenNames["app:"+app.Name] {
			v.add("%s.name %q is duplicated", prefix, app.Name)
		}
		seenNames["app:"+app.Name] = true

		if len(app.Hostnames) == 0 {
			v.add("%s.hostnames must not be empty", prefix)
		}
		for _, host := range app.Hostnames {
			clean := strings.ToLower(strings.TrimSpace(host))
			if clean == "" {
				v.add("%s.hostnames contains an empty entry", prefix)
				continue
			}
			if other, ok := seenHosts[clean]; ok {
				v.add("%s hostname %q is already declared by %s", prefix, clean, other)
			}
			seenHosts[clean] = prefix
		}

		switch app.RoutingType {
		case "proxy":
			if len(app.Upstreams) == 0 {
				v.add("%s.upstreams is required when routing_type is proxy", prefix)
			}
		case "static":
			if app.DocumentRoot == "" {
				v.add("%s.document_root is required when routing_type is static", prefix)
			}
		case "redirect":
			if app.RedirectURL == "" {
				v.add("%s.redirect_url is required when routing_type is redirect", prefix)
			}
			if !validRedirectStatus(app.RedirectStatus) {
				v.add("%s.redirect_status %d must be 301, 302, 307, or 308", prefix, app.RedirectStatus)
			}
		default:
			v.add("%s.routing_type %q must be proxy, static, or redirect", prefix, app.RoutingType)
		}

		switch app.SSLMode {
		case "none", "auto", "manual":
		default:
			v.add("%s.ssl_mode %q must be none, auto, or manual", prefix, app.SSLMode)
		}
		if app.SSLMode == "manual" && app.Certificate == "" {
			v.add("%s.certificate is required when ssl_mode is manual", prefix)
		}
		for j, up := range app.Upstreams {
			if !validDial(up.Dial) {
				v.add("%s.upstreams[%d].dial %q is not a valid host:port", prefix, j, up.Dial)
			}
			if up.Weight < 0 || up.MaxFails < 0 {
				v.add("%s.upstreams[%d] weights and max_fails must be non-negative", prefix, j)
			}
		}
	}

	for i, cert := range f.Certificates {
		prefix := fmt.Sprintf("certificates[%d]", i)
		if !validName(cert.Name) {
			v.add("%s.name %q must be a slug", prefix, cert.Name)
		} else if seenNames["cert:"+cert.Name] {
			v.add("%s.name %q is duplicated", prefix, cert.Name)
		}
		seenNames["cert:"+cert.Name] = true
		if len(cert.Domains) == 0 {
			v.add("%s.domains must not be empty", prefix)
		}
		switch cert.Source {
		case "upload", "self-signed", "acme":
		default:
			v.add("%s.source %q must be upload, self-signed, or acme", prefix, cert.Source)
		}
		if cert.Source == "upload" && (cert.CertPEM == "" || cert.KeyPEM == "") {
			v.add("%s.cert_pem and key_pem are required for upload certificates", prefix)
		}
	}

	for i, rule := range f.ACLs {
		prefix := fmt.Sprintf("acls[%d]", i)
		if !validName(rule.Name) {
			v.add("%s.name %q must be a slug", prefix, rule.Name)
		} else if seenNames["acl:"+rule.Name] {
			v.add("%s.name %q is duplicated", prefix, rule.Name)
		}
		seenNames["acl:"+rule.Name] = true
		if strings.TrimSpace(rule.Expression) == "" {
			v.add("%s.expression is required", prefix)
		}
		switch rule.Action {
		case "allow", "block", "challenge", "redirect", "audit":
		default:
			v.add("%s.action %q must be allow, block, challenge, redirect, or audit", prefix, rule.Action)
		}
		if rule.Action == "redirect" && rule.RedirectURL == "" {
			v.add("%s.redirect_url is required for redirect rules", prefix)
		}
	}

	for i, exc := range f.Exceptions {
		prefix := fmt.Sprintf("exceptions[%d]", i)
		if exc.Name != "" && !validName(exc.Name) {
			v.add("%s.name %q must be a slug", prefix, exc.Name)
		}
		if exc.Path == "" && exc.PathPrefix == "" && exc.PathRegex == "" {
			v.add("%s requires path, path_prefix, or path_regex", prefix)
		}
	}

	for i, group := range f.IPGroups {
		prefix := fmt.Sprintf("ip_groups[%d]", i)
		if !validName(group.Name) {
			v.add("%s.name %q must be a slug", prefix, group.Name)
		} else if seenNames["ipg:"+group.Name] {
			v.add("%s.name %q is duplicated", prefix, group.Name)
		}
		seenNames["ipg:"+group.Name] = true
		for j, entry := range group.Entries {
			if _, _, err := net.ParseCIDR(entry.CIDR); err != nil {
				v.add("%s.entries[%d].cidr %q is not a valid CIDR", prefix, j, entry.CIDR)
			}
		}
	}

	for i, policy := range f.RatePolicies {
		prefix := fmt.Sprintf("rate_policies[%d]", i)
		if !validName(policy.Name) {
			v.add("%s.name %q must be a slug", prefix, policy.Name)
		} else if seenNames["rate:"+policy.Name] {
			v.add("%s.name %q is duplicated", prefix, policy.Name)
		}
		seenNames["rate:"+policy.Name] = true
		if policy.Host == "" {
			v.add("%s.host is required (use \"*\" for the global default)", prefix)
		}
	}

	for i, policy := range f.BotPolicies {
		prefix := fmt.Sprintf("bot_policies[%d]", i)
		if !validName(policy.Name) {
			v.add("%s.name %q must be a slug", prefix, policy.Name)
		} else if seenNames["bot:"+policy.Name] {
			v.add("%s.name %q is duplicated", prefix, policy.Name)
		}
		seenNames["bot:"+policy.Name] = true
		if policy.Host == "" {
			v.add("%s.host is required (use \"*\" for the global default)", prefix)
		}
	}

	for i, provider := range f.IdentityProviders {
		prefix := fmt.Sprintf("identity_providers[%d]", i)
		if !validName(provider.Name) {
			v.add("%s.name %q must be a slug", prefix, provider.Name)
		} else if seenNames["idp:"+provider.Name] {
			v.add("%s.name %q is duplicated", prefix, provider.Name)
		}
		seenNames["idp:"+provider.Name] = true
		switch provider.Type {
		case "oidc", "ldap", "github":
		default:
			v.add("%s.type %q must be oidc, ldap, or github", prefix, provider.Type)
		}
	}

	for i, tmpl := range f.Templates {
		prefix := fmt.Sprintf("templates[%d]", i)
		if !validStatus(tmpl.StatusCode) {
			v.add("%s.status_code %d must be between 200 and 599", prefix, tmpl.StatusCode)
		}
		if seenNames[fmt.Sprintf("tmpl:%d", tmpl.StatusCode)] {
			v.add("%s.status_code %d is duplicated", prefix, tmpl.StatusCode)
		}
		seenNames[fmt.Sprintf("tmpl:%d", tmpl.StatusCode)] = true
		if strings.TrimSpace(tmpl.ContentHTML) == "" {
			v.add("%s.content_html is required", prefix)
		}
	}

	if f.Detector != nil {
		for module, mode := range f.Detector.Modules {
			switch strings.ToLower(mode) {
			case "disabled", "audit", "balance", "strict":
			default:
				v.add("detector.modules.%s mode %q must be disabled, audit, balance, or strict", module, mode)
			}
		}
	}
}

func enabled(v *bool) bool { return v == nil || *v }

func validStatus(code int) bool { return code >= 200 && code <= 599 }

func validRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 307 || code == 308
}

func validListen(addr string) bool {
	if addr == "" {
		return false
	}
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port != ""
}

func validDial(dial string) bool {
	if dial == "" {
		return false
	}
	if strings.HasPrefix(dial, "unix/") {
		return true
	}
	host, port, err := net.SplitHostPort(dial)
	return err == nil && host != "" && port != ""
}

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
