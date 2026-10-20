package caddy

import (
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseAuth(d *caddyfile.Dispenser) error {
	if m.AuthConfig == nil {
		m.AuthConfig = new(AuthSettings)
	}
	for d.NextBlock(1) {
		switch d.Val() {
		case "provider":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.Provider = strings.ToLower(d.Val())
		case "issuer", "issuer_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.IssuerURL = d.Val()
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.ClientID = d.Val()
		case "client_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.ClientSecret = d.Val()
		case "redirect_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.RedirectURL = d.Val()
		case "scopes", "scope":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AuthConfig.Scopes = append(m.AuthConfig.Scopes, args...)
		case "bypass_path", "bypass_paths":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AuthConfig.BypassPaths = append(m.AuthConfig.BypassPaths, args...)
		case "session_secret", "cookie_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.SessionSecret = d.Val()
		case "session_cookie", "cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthConfig.SessionCookie = d.Val()
		case "session_ttl", "cookie_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid session_ttl: %s (%v)", d.Val(), err)
			}
			m.AuthConfig.SessionTTL = caddy.Duration(dur)
		case "session_secure", "cookie_secure":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
			var sec bool
			switch strings.ToLower(val) {
			case "true", "on", "yes", "1", "enabled":
				sec = true
			case "false", "off", "no", "0", "disabled":
				sec = false
			default:
				return d.Errf("invalid session_secure value: %s (must be true/false/on/off)", val)
			}
			m.AuthConfig.SessionSecure = &sec
		case "user":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return d.ArgErr()
			}
			u := auth.SimpleUser{
				Username:     args[0],
				PasswordHash: args[1],
			}
			if len(args) >= 3 {
				u.Roles = strings.Split(args[2], ",")
			}
			m.AuthConfig.Users = append(m.AuthConfig.Users, u)
		}
	}
	return nil
}
