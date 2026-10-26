package control

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// ValidationError represents an individual configuration issue.
type ValidationError struct {
	Entity string `json:"entity"`
	ID     string `json:"id"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("[%s:%s] %s: %s", e.Entity, e.ID, e.Field, e.Reason)
}

// ValidationErrors collects multiple validation errors.
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "no validation errors"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("configuration validation failed with %d error(s):\n", len(ve.Errors)))
	for _, e := range ve.Errors {
		sb.WriteString("  - ")
		sb.WriteString(e.Error())
		sb.WriteString("\n")
	}
	return sb.String()
}

// ValidateSnapshot performs strict pre-flight validation on an assembled ConfigSnapshot.
func ValidateSnapshot(snap *ConfigSnapshot) error {
	if snap == nil {
		return &ValidationErrors{
			Errors: []ValidationError{
				{Entity: "Snapshot", ID: "root", Field: "snapshot", Reason: "snapshot cannot be nil"},
			},
		}
	}

	var errs []ValidationError

	if !snap.DefaultMode.IsValid() {
		errs = append(errs, ValidationError{
			Entity: "Snapshot",
			ID:     "root",
			Field:  "default_mode",
			Reason: fmt.Sprintf("invalid default run mode %q", snap.DefaultMode),
		})
	}

	// Validate Apps
	for appID, app := range snap.Apps {
		if app == nil {
			errs = append(errs, ValidationError{
				Entity: "App",
				ID:     appID,
				Field:  "app",
				Reason: "app configuration cannot be nil",
			})
			continue
		}

		if app.ID == "" {
			errs = append(errs, ValidationError{
				Entity: "App",
				ID:     appID,
				Field:  "id",
				Reason: "app ID cannot be empty",
			})
		}
		if app.Name == "" {
			errs = append(errs, ValidationError{
				Entity: "App",
				ID:     app.ID,
				Field:  "name",
				Reason: "app name cannot be empty",
			})
		}
		if !app.Mode.IsValid() {
			errs = append(errs, ValidationError{
				Entity: "App",
				ID:     app.ID,
				Field:  "mode",
				Reason: fmt.Sprintf("invalid run mode %q", app.Mode),
			})
		}
		if len(app.Hostnames) == 0 {
			errs = append(errs, ValidationError{
				Entity: "App",
				ID:     app.ID,
				Field:  "hostnames",
				Reason: "app must have at least one hostname configured",
			})
		}
		for _, host := range app.Hostnames {
			cleanHost := strings.TrimSpace(host)
			if cleanHost == "" {
				errs = append(errs, ValidationError{
					Entity: "App",
					ID:     app.ID,
					Field:  "hostnames",
					Reason: "hostname cannot be empty or whitespace",
				})
			}
		}

		// Validate routing and TLS metadata.
		errs = append(errs, validateAppRouting(app)...)

		// Validate Upstreams
		for idx, up := range app.Upstreams {
			if strings.TrimSpace(up.Dial) == "" {
				errs = append(errs, ValidationError{
					Entity: "Upstream",
					ID:     fmt.Sprintf("%s:%d", app.ID, idx),
					Field:  "dial",
					Reason: "upstream dial address cannot be empty",
				})
			} else if !isValidDialAddress(up.Dial) {
				errs = append(errs, ValidationError{
					Entity: "Upstream",
					ID:     fmt.Sprintf("%s:%d", app.ID, idx),
					Field:  "dial",
					Reason: fmt.Sprintf("invalid upstream dial address %q (expected host:port or unix:/path)", up.Dial),
				})
			}
			if up.Weight < 0 {
				errs = append(errs, ValidationError{
					Entity: "Upstream",
					ID:     fmt.Sprintf("%s:%d", app.ID, idx),
					Field:  "weight",
					Reason: "upstream weight must be non-negative",
				})
			}
		}
	}

	// Validate Exceptions
	for _, exc := range snap.Exceptions {
		if exc == nil {
			continue
		}
		if exc.ID == "" {
			errs = append(errs, ValidationError{
				Entity: "Exception",
				ID:     "unknown",
				Field:  "id",
				Reason: "exception ID cannot be empty",
			})
		}
		if exc.PathRegex != "" {
			if _, err := regexp.Compile(exc.PathRegex); err != nil {
				errs = append(errs, ValidationError{
					Entity: "Exception",
					ID:     exc.ID,
					Field:  "path_regex",
					Reason: fmt.Sprintf("invalid path_regex pattern %q: %v", exc.PathRegex, err),
				})
			}
		}
		if exc.ParamRegex != "" {
			if _, err := regexp.Compile(exc.ParamRegex); err != nil {
				errs = append(errs, ValidationError{
					Entity: "Exception",
					ID:     exc.ID,
					Field:  "param_regex",
					Reason: fmt.Sprintf("invalid param_regex pattern %q: %v", exc.ParamRegex, err),
				})
			}
		}
	}

	// Validate ACL Rules
	for _, rule := range snap.ACLRules {
		if rule == nil {
			continue
		}
		if rule.Name == "" {
			errs = append(errs, ValidationError{
				Entity: "ACLRule",
				ID:     "unknown",
				Field:  "name",
				Reason: "ACL rule name cannot be empty",
			})
		}

		if err := rule.Compile(nil); err != nil {
			errs = append(errs, ValidationError{
				Entity: "ACLRule",
				ID:     rule.Name,
				Field:  "expression",
				Reason: fmt.Sprintf("invalid expr syntax: %v", err),
			})
		}

		switch rule.Action {
		case acl.ActionAllow, acl.ActionBlock, acl.ActionChallenge, acl.ActionRedirect, acl.ActionAudit:
		default:
			errs = append(errs, ValidationError{
				Entity: "ACLRule",
				ID:     rule.Name,
				Field:  "action",
				Reason: fmt.Sprintf("unsupported ACL action %q", rule.Action),
			})
		}

		if rule.Action == acl.ActionRedirect && strings.TrimSpace(rule.RedirectURL) == "" {
			errs = append(errs, ValidationError{
				Entity: "ACLRule",
				ID:     rule.Name,
				Field:  "redirect_url",
				Reason: "redirect_url must be specified for redirect action",
			})
		}
	}

	// Validate Rate Policies
	for _, rp := range snap.RatePolicies {
		if rp == nil {
			continue
		}
		if rp.Tier1Rate <= 0 {
			errs = append(errs, ValidationError{
				Entity: "RatePolicy",
				ID:     rp.ID,
				Field:  "tier1_rate",
				Reason: "tier1_rate must be greater than zero",
			})
		}
		if rp.Tier1Burst < 0 {
			errs = append(errs, ValidationError{
				Entity: "RatePolicy",
				ID:     rp.ID,
				Field:  "tier1_burst",
				Reason: "tier1_burst must be non-negative",
			})
		}
		if rp.Tier1Period <= 0 {
			errs = append(errs, ValidationError{
				Entity: "RatePolicy",
				ID:     rp.ID,
				Field:  "tier1_period",
				Reason: "tier1_period must be greater than zero",
			})
		}
	}

	// Validate Bot Configs
	for _, bc := range snap.BotConfigs {
		if bc == nil {
			continue
		}
		if bc.PowEnabled && (bc.PowDifficulty < 1000 || bc.PowDifficulty > 200000) {
			errs = append(errs, ValidationError{
				Entity: "BotConfig",
				ID:     bc.ID,
				Field:  "pow_difficulty",
				Reason: fmt.Sprintf("pow_difficulty %d out of bounds (must be 1,000-200,000)", bc.PowDifficulty),
			})
		}
		for _, trap := range bc.TrapURLs {
			if !strings.HasPrefix(trap, "/") {
				errs = append(errs, ValidationError{
					Entity: "BotConfig",
					ID:     bc.ID,
					Field:  "trap_urls",
					Reason: fmt.Sprintf("trap URL %q must begin with /", trap),
				})
			}
		}
	}

	// Validate Semantic Detector Matrix (global + per-app overrides)
	if snap.SemanticDefaults != nil {
		for module, mode := range snap.SemanticDefaults {
			if !waf.IsValidModule(module) {
				errs = append(errs, ValidationError{
					Entity: "Detector",
					ID:     string(module),
					Field:  "module",
					Reason: fmt.Sprintf("unknown semantic module %q", module),
				})
				continue
			}
			if mode > waf.ModeStrict {
				errs = append(errs, ValidationError{
					Entity: "Detector",
					ID:     string(module),
					Field:  "mode",
					Reason: fmt.Sprintf("semantic mode %d out of range (0-3)", uint8(mode)),
				})
			}
		}
	}
	for appID, app := range snap.Apps {
		if app == nil || len(app.SemanticPolicy) == 0 {
			continue
		}
		for module, mode := range app.SemanticPolicy {
			if !waf.IsValidModule(module) {
				errs = append(errs, ValidationError{
					Entity: "Detector",
					ID:     appID + "/" + string(module),
					Field:  "module",
					Reason: fmt.Sprintf("unknown semantic module %q in per-app policy", module),
				})
				continue
			}
			if mode > waf.ModeStrict {
				errs = append(errs, ValidationError{
					Entity: "Detector",
					ID:     appID + "/" + string(module),
					Field:  "mode",
					Reason: fmt.Sprintf("semantic mode %d out of range (0-3)", uint8(mode)),
				})
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationErrors{Errors: errs}
	}
	return nil
}

// validateAppRouting validates port metadata, TLS mode, routing strategy, and
// the fields each routing strategy depends on.
func validateAppRouting(app *AppConfig) []ValidationError {
	var errs []ValidationError
	add := func(field, reason string) {
		errs = append(errs, ValidationError{Entity: "App", ID: app.ID, Field: field, Reason: reason})
	}

	if _, err := NormalizeRoutingType(app.RoutingType); err != nil {
		add("routing_type", err.Error())
	}
	if _, err := NormalizeSSLMode(app.SSLMode); err != nil {
		add("ssl_mode", err.Error())
	}
	if _, err := NormalizeLoadBalancing(app.LoadBalancing); err != nil {
		add("load_balancing", err.Error())
	}
	if _, err := NormalizePorts(app.Ports); err != nil {
		add("ports", err.Error())
	}
	if HasHTTPSPort(app.Ports) && (app.SSLMode == "" || app.SSLMode == SSLModeNone) {
		add("ssl_mode", "an https listening port requires ssl_mode 'auto' or 'manual'")
	}
	if app.SSLMode == SSLModeManual && strings.TrimSpace(app.CertificateID) == "" {
		add("certificate_id", "ssl_mode 'manual' requires a certificate_id")
	}

	switch app.RoutingType {
	case RoutingStatic:
		if strings.TrimSpace(app.DocumentRoot) == "" {
			add("document_root", "static routing requires a document root")
		} else if !filepath.IsAbs(app.DocumentRoot) {
			add("document_root", "document root must be an absolute path")
		}
	case RoutingRedirect:
		if !IsValidRedirectTarget(app.RedirectURL) {
			add("redirect_url", "redirect routing requires an absolute http(s) URL or a site-relative path")
		}
		if !IsValidRedirectStatus(app.RedirectStatus) {
			add("redirect_status", fmt.Sprintf("unsupported redirect status %d (expected 301, 302, 307, or 308)", app.RedirectStatus))
		}
	}
	return errs
}

func isValidDialAddress(addr string) bool {
	clean := strings.TrimSpace(addr)
	if strings.HasPrefix(clean, "unix:") {
		return len(clean) > 5
	}

	host, portStr, err := net.SplitHostPort(clean)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}
