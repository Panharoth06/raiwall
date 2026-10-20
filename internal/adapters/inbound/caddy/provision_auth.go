package caddy

import (
	"time"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func (m *Middleware) provisionAuth(ctx caddy.Context) error {
	if m.authGateway == nil && m.AuthConfig != nil {
		gwCfg := auth.GatewayConfig{
			BypassPaths: m.AuthConfig.BypassPaths,
		}
		if len(m.AuthConfig.Users) > 0 || m.AuthConfig.Provider == "simple" || m.AuthConfig.Provider == "dual" {
			gwCfg.SimpleAuth = auth.NewSimpleAuth(m.AuthConfig.Users...)
		}
		var sessionOpts []auth.SessionOption
		if m.AuthConfig.SessionCookie != "" {
			sessionOpts = append(sessionOpts, auth.WithCookieName(m.AuthConfig.SessionCookie))
		}
		if m.AuthConfig.SessionTTL > 0 {
			sessionOpts = append(sessionOpts, auth.WithCookieTTL(time.Duration(m.AuthConfig.SessionTTL)))
		}
		if m.AuthConfig.SessionSecure != nil {
			sessionOpts = append(sessionOpts, auth.WithCookieSecure(*m.AuthConfig.SessionSecure))
		}
		gwCfg.SessionMgr = auth.NewSessionManager(m.AuthConfig.SessionSecret, sessionOpts...)

		if m.AuthConfig.IssuerURL != "" && (m.AuthConfig.Provider == "oidc" || m.AuthConfig.Provider == "dual") {
			oidcCfg := auth.OIDCConfig{
				IssuerURL:    m.AuthConfig.IssuerURL,
				ClientID:     m.AuthConfig.ClientID,
				ClientSecret: m.AuthConfig.ClientSecret,
				RedirectURL:  m.AuthConfig.RedirectURL,
				Scopes:       m.AuthConfig.Scopes,
			}
			oidcClient, err := auth.NewOIDCClient(ctx, oidcCfg)
			if err != nil {
				if m.logger != nil {
					m.logger.Warn("Failed to initialize OIDC client during provision", zap.Error(err))
				}
			} else {
				gwCfg.OIDCClient = oidcClient
			}
		}
		m.authGateway = auth.NewAuthGateway(gwCfg)
	}

	return nil
}
