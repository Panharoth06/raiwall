package proxy

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
//
// Syntax:
//
//	raiwall [<mode>] {
//	    mode <defense|audit|offline>
//	    block_status <code>
//	    offline_status <code>
//	    strip_headers <header1> [<header2>...]
//	    ast_timeout <duration>
//	    max_param_size <bytes>
//	}
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

			default:
				return d.Errf("unrecognized raiwall subdirective: %s", d.Val())
			}
		}
	}

	return nil
}
