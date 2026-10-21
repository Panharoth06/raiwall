package caddy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseStorage(d *caddyfile.Dispenser) error {
	if m.StorageConfig == nil {
		m.StorageConfig = &StorageSettings{
			Stores: make(map[string]StorageStoreSettings),
		}
	}
	if m.StorageConfig.Stores == nil {
		m.StorageConfig.Stores = make(map[string]StorageStoreSettings)
	}

	for d.NextBlock(1) {
		switch d.Val() {
		case "store":
			if !d.NextArg() {
				return d.ArgErr()
			}
			storeName := d.Val()
			var store StorageStoreSettings

			for d.NextBlock(2) {
				switch d.Val() {
				case "driver":
					if !d.NextArg() {
						return d.ArgErr()
					}
					store.Driver = d.Val()
				case "dsn":
					if !d.NextArg() {
						return d.ArgErr()
					}
					store.DSN = d.Val()
				case "max_open":
					if !d.NextArg() {
						return d.ArgErr()
					}
					n, err := strconv.Atoi(d.Val())
					if err != nil || n <= 0 {
						return d.Errf("invalid max_open: %s", d.Val())
					}
					store.MaxOpen = n
				case "max_idle":
					if !d.NextArg() {
						return d.ArgErr()
					}
					n, err := strconv.Atoi(d.Val())
					if err != nil || n <= 0 {
						return d.Errf("invalid max_idle: %s", d.Val())
					}
					store.MaxIdle = n
				case "retention":
					if !d.NextArg() {
						return d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return d.Errf("invalid retention: %s", d.Val())
					}
					store.Retention = caddy.Duration(dur)
				case "prune_interval":
					if !d.NextArg() {
						return d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return d.Errf("invalid prune_interval: %s", d.Val())
					}
					store.PruneInterval = caddy.Duration(dur)
				default:
					return d.Errf("unrecognized store option: %s", d.Val())
				}
			}
			m.StorageConfig.Stores[storeName] = store

		case "control":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.StorageConfig.Control = d.Val()

		case "telemetry":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.StorageConfig.Telemetry = d.Val()

		default:
			return d.Errf("unrecognized storage option: %s", d.Val())
		}
	}
	return nil
}
