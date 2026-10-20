package caddy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("raiwall", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("raiwall", httpcaddyfile.Before, "reverse_proxy")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Middleware)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Optional first positional argument: raiwall [<mode>]
		if d.NextArg() {
			m.Mode = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Mode = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			case "block_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				code, err := strconv.Atoi(d.Val())
				if err != nil || code < 200 || code > 599 {
					return d.Errf("invalid block_status code: %s (must be between 200 and 599)", d.Val())
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				m.BlockStatusCode = code

			case "offline_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				code, err := strconv.Atoi(d.Val())
				if err != nil || code < 200 || code > 599 {
					return d.Errf("invalid offline_status code: %s (must be between 200 and 599)", d.Val())
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				m.OfflineStatusCode = code

			case "strip_headers":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.StripHeaders = append(m.StripHeaders, args...)

			case "ast_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ast_timeout: %s (%v)", d.Val(), err)
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				m.ASTTimeout = caddy.Duration(dur)

			case "max_param_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				size, err := strconv.Atoi(d.Val())
				if err != nil || size <= 0 {
					return d.Errf("invalid max_param_size: %s (must be a positive integer in bytes)", d.Val())
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				m.MaxParamSize = size

			case "bot_defense":
				if err := m.parseBotDefense(d); err != nil {
					return err
				}

			case "pow_difficulty":
				if err := m.parsePoWDifficulty(d); err != nil {
					return err
				}

			case "clearance_ttl":
				if err := m.parseClearanceTTL(d); err != nil {
					return err
				}

			case "honeypot", "honeypot_trap":
				if err := m.parseHoneypot(d); err != nil {
					return err
				}

			case "rate_limit":
				if err := m.parseRateLimit(d); err != nil {
					return err
				}

			case "waiting_room":
				if err := m.parseWaitingRoom(d); err != nil {
					return err
				}

			case "exceptions":
				if err := m.parseExceptions(d); err != nil {
					return err
				}

			case "acl":
				if err := m.parseACL(d); err != nil {
					return err
				}

			case "auth":
				if err := m.parseAuth(d); err != nil {
					return err
				}

			case "telemetry":
				if err := m.parseTelemetry(d); err != nil {
					return err
				}

			case "control":
				if err := m.parseControl(d); err != nil {
					return err
				}

			case "sidecar":
				if err := m.parseSidecar(d); err != nil {
					return err
				}

			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}
