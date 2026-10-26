package caddy

import (
	"time"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// provisionAuth compiles the global `auth` block into the shared HTTP 467
// portal backends (local users + OIDC). The legacy AuthGateway login page is
// retired; the portal is the single browser login surface.
func (m *Middleware) provisionAuth(ctx caddy.Context) error {
	if m.AuthConfig == nil {
		return nil
	}

	cfg := m.AuthConfig
	if len(cfg.Users) > 0 || cfg.Provider == "simple" || cfg.Provider == "dual" {
		m.globalAuthUsers = auth.NewSimpleAuth(cfg.Users...)
	}

	if cfg.IssuerURL != "" && (cfg.Provider == "oidc" || cfg.Provider == "dual") {
		oidcClient, err := auth.NewOIDCClient(ctx, auth.OIDCConfig{
			IssuerURL:    cfg.IssuerURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		})
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("Failed to initialize OIDC client during provision", zap.Error(err))
			}
		} else {
			m.globalAuthOIDC = oidcClient.SetName("SSO")
		}
	}

	return nil
}

// authSessionTTL returns the configured portal cookie lifetime.
func (m *Middleware) authSessionTTL() time.Duration {
	if m.AuthConfig != nil && m.AuthConfig.SessionTTL > 0 {
		return time.Duration(m.AuthConfig.SessionTTL)
	}
	return 0
}
