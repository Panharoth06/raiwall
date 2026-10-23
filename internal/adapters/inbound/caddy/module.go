package caddy

import (
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(new(Middleware))
}

// CaddyModule returns the Caddy module information.
// Pointer receiver: Middleware carries a sync.Mutex for the app auth gate
// cache and must never be copied.
func (*Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.raiwall",
		New: func() caddy.Module { return new(Middleware) },
	}
}
