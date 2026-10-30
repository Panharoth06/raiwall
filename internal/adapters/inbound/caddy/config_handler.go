package caddy

import (
	"fmt"
	"strings"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/caddyserver/caddy/v2"
	"golang.org/x/crypto/bcrypt"
)

// handlerFromConfig projects the declarative document onto the Caddy handler
// module settings. The declarative schema is the public contract; this is the
// only place it is translated into runtime configuration.
func handlerFromConfig(file *config.File) (*Middleware, error) {
	m := &Middleware{
		Mode:                file.WAF.Mode,
		BlockStatusCode:     file.WAF.BlockStatusCode,
		BlockResponseBody:   file.WAF.BlockResponseBody,
		OfflineStatusCode:   file.WAF.OfflineStatusCode,
		OfflineResponseBody: file.WAF.OfflineResponseBody,
		StripHeaders:        file.WAF.StripHeaders,
		ASTTimeout:          caddy.Duration(file.WAF.ASTTimeout),
		MaxParamSize:        file.WAF.MaxParamSize,

		BotDefense:    file.Bot.Defense,
		PoWDifficulty: file.Bot.PoWDifficulty,
		PoWSecret:     file.Bot.PoWSecret,
		ClearanceTTL:  caddy.Duration(file.Bot.ClearanceTTL),
		HoneypotTrap:  file.Bot.HoneypotTrap,
	}

	if file.RateLimit != nil {
		m.RateLimitConfig = &RateLimitSettings{
			Tier1Rate:        file.RateLimit.Tier1Rate,
			Tier1Period:      caddy.Duration(file.RateLimit.Tier1Period),
			Tier1Burst:       file.RateLimit.Tier1Burst,
			Tier2Threshold:   file.RateLimit.Tier2Threshold,
			Tier2Window:      caddy.Duration(file.RateLimit.Tier2Window),
			Tier2BanDuration: caddy.Duration(file.RateLimit.Tier2BanDuration),
			Tier3Threshold:   file.RateLimit.Tier3Threshold,
			Tier3Window:      caddy.Duration(file.RateLimit.Tier3Window),
			Tier3BanDuration: caddy.Duration(file.RateLimit.Tier3BanDuration),
			StorageType:      file.RateLimit.Storage,
			StorageAddr:      file.RateLimit.StorageAddr,
		}
	}

	if file.WaitingRoom != nil {
		m.WaitingRoomConfig = &WaitingRoomSettings{
			Enabled:               boolValue(file.WaitingRoom.Enabled, file.WaitingRoom.MaxConcurrentInFlight > 0),
			MaxConcurrentInFlight: file.WaitingRoom.MaxConcurrentInFlight,
			MaxQueueDepth:         file.WaitingRoom.MaxQueueDepth,
			AdmissionRate:         file.WaitingRoom.AdmissionRate,
			AdmissionTokenTTL:     caddy.Duration(file.WaitingRoom.AdmissionTokenTTL),
			TargetPaths:           file.WaitingRoom.TargetPaths,
		}
	}

	if len(file.Exceptions) > 0 {
		rules := make([]*acl.ExceptionRule, 0, len(file.Exceptions))
		for i, exc := range file.Exceptions {
			id := exc.Name
			if id == "" {
				id = fmt.Sprintf("exception-%d", i+1)
			}
			prefix := exc.PathPrefix
			if prefix == "" {
				prefix = exc.Path
			}
			rules = append(rules, &acl.ExceptionRule{
				ID:          id,
				Description: exc.Description,
				Host:        exc.Host,
				PathRegex:   exc.PathRegex,
				PathPrefix:  prefix,
				Method:      exc.Method,
				Location:    exc.Location,
				ParamName:   exc.ParamName,
				ParamRegex:  exc.ParamRegex,
				RuleID:      exc.RuleID,
			})
		}
		m.ExceptionConfig = &ExceptionSettings{Rules: rules}
	}

	if len(file.ACLs) > 0 || len(file.ThreatFeeds) > 0 || file.GeoIP.Country != "" ||
		file.GeoIP.City != "" || file.GeoIP.ASN != "" || file.GeoIP.AutoUpdate {
		aclCfg := &ACLSettings{
			ThreatFeeds:     file.ThreatFeeds,
			GeoIPCountry:    file.GeoIP.Country,
			GeoIPCity:       file.GeoIP.City,
			GeoIPASN:        file.GeoIP.ASN,
			GeoIPAutoUpdate: file.GeoIP.AutoUpdate,
		}
		for _, rule := range file.ACLs {
			aclCfg.Rules = append(aclCfg.Rules, &acl.ACLRule{
				Name:               rule.Name,
				Expression:         rule.Expression,
				Action:             acl.Action(strings.ToLower(rule.Action)),
				Priority:           int(rule.Priority),
				StatusCode:         int(rule.StatusCode),
				RedirectURL:        rule.RedirectURL,
				ContinueInspection: rule.ContinueInspection != nil && *rule.ContinueInspection,
			})
		}
		m.ACLConfig = aclCfg
	}

	authCfg, err := authSettings(file.Auth)
	if err != nil {
		return nil, err
	}
	m.AuthConfig = authCfg

	if file.Telemetry != nil {
		tel := &TelemetrySettings{
			FlushInterval: caddy.Duration(file.Telemetry.FlushInterval),
			BufferSize:    file.Telemetry.BufferSize,
			Retention:     caddy.Duration(file.Telemetry.Retention),
		}
		for _, ch := range file.Telemetry.AlertChannels {
			tel.AlertChannels = append(tel.AlertChannels, AlertChannelSettings{
				Name:     ch.Name,
				URL:      ch.URL,
				Events:   ch.Events,
				Cooldown: caddy.Duration(ch.Cooldown),
			})
		}
		m.TelemetryConfig = tel
	}

	m.StorageConfig = storageSettings(file.Storage)
	m.ControlConfig = &ControlSettings{
		HMACSecret: file.Control.HMACSecret,
		BootstrapAdmin: &BootstrapAdminSettings{
			Username: file.Control.BootstrapAdmin.Username,
			Password: file.Control.BootstrapAdmin.Password,
			Role:     file.Control.BootstrapAdmin.Role,
		},
	}

	if file.Sidecar != nil && boolValue(file.Sidecar.Enabled, true) {
		m.SidecarConfig = &SidecarSettings{
			Listen:      file.Sidecar.Listen,
			MaxBodySize: file.Sidecar.MaxBodySize,
		}
	}

	if file.Declarative.Mode != "" && file.Declarative.Mode != "off" {
		m.DeclarativeConfig = file.Resources()
	}

	return m, nil
}

func authSettings(authCfg *config.Auth) (*AuthSettings, error) {
	if authCfg == nil {
		return nil, nil
	}

	users := make([]auth.SimpleUser, 0, len(authCfg.Users))
	for _, user := range authCfg.Users {
		hash := user.PasswordHash
		if hash == "" && user.Password != "" {
			generated, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, fmt.Errorf("hash password for auth user %q: %w", user.Username, err)
			}
			hash = string(generated)
		}
		users = append(users, auth.SimpleUser{
			Username:     user.Username,
			PasswordHash: hash,
			Email:        user.Email,
			Name:         user.Name,
			Roles:        user.Roles,
		})
	}

	return &AuthSettings{
		Provider:      authCfg.Provider,
		IssuerURL:     authCfg.IssuerURL,
		ClientID:      authCfg.ClientID,
		ClientSecret:  authCfg.ClientSecret,
		RedirectURL:   authCfg.RedirectURL,
		Scopes:        authCfg.Scopes,
		Users:         users,
		SessionSecret: authCfg.SessionSecret,
		SessionCookie: authCfg.SessionCookie,
		SessionTTL:    caddy.Duration(authCfg.SessionTTL),
		SessionSecure: authCfg.SessionSecure,
		BypassPaths:   authCfg.BypassPaths,
	}, nil
}

func storageSettings(storage config.Storage) *StorageSettings {
	settings := &StorageSettings{
		Stores:    make(map[string]StorageStoreSettings, len(storage.Stores)),
		Control:   storage.Control,
		Telemetry: storage.Telemetry,
	}
	for name, store := range storage.Stores {
		settings.Stores[name] = StorageStoreSettings{
			Driver:        store.Driver,
			DSN:           store.DSN,
			MaxOpen:       store.MaxOpen,
			MaxIdle:       store.MaxIdle,
			Retention:     caddy.Duration(store.Retention),
			PruneInterval: caddy.Duration(store.PruneInterval),
		}
	}
	return settings
}

func boolValue(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}
