package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/pkg/acl"
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

		// Compile expr bytecode
		if err := rule.Compile(nil); err != nil {
			errs = append(errs, ValidationError{
				Entity: "ACLRule",
				ID:     rule.Name,
				Field:  "expression",
				Reason: fmt.Sprintf("invalid expr syntax: %v", err),
			})
		}

		// Action verification
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
		if bc.PowEnabled && (bc.PowDifficulty < 1 || bc.PowDifficulty > 32) {
			errs = append(errs, ValidationError{
				Entity: "BotConfig",
				ID:     bc.ID,
				Field:  "pow_difficulty",
				Reason: fmt.Sprintf("pow_difficulty %d out of bounds (must be 1-32)", bc.PowDifficulty),
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

	if len(errs) > 0 {
		return &ValidationErrors{Errors: errs}
	}
	return nil
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
