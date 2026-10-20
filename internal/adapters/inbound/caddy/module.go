package caddy

import (
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.raiwall",
		New: func() caddy.Module { return new(Middleware) },
	}
}
