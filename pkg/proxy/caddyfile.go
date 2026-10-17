package proxy

import (
	"strconv"

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
//	}
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Optional first positional argument: raiwall <mode>
		if d.NextArg() {
			m.Mode = d.Val()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Mode = d.Val()

			case "block_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				code, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid block_status code: %v", err)
				}
				m.BlockStatusCode = code

			case "offline_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				code, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid offline_status code: %v", err)
				}
				m.OfflineStatusCode = code

			case "strip_headers":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.StripHeaders = append(m.StripHeaders, args...)

			default:
				return d.Errf("unrecognized raiwall subdirective: %s", d.Val())
			}
		}
	}

	return nil
}
