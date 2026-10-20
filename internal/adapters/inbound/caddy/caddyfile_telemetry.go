package caddy

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseTelemetry(d *caddyfile.Dispenser) error {
	if m.TelemetryConfig == nil {
		m.TelemetryConfig = new(TelemetrySettings)
	}
	for d.NextBlock(1) {
		switch d.Val() {
		case "storage":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.TelemetryConfig.StorageType = d.Val()
			if d.NextArg() {
				m.TelemetryConfig.StoragePath = d.Val()
			}
		case "flush_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid flush_interval: %s (%v)", d.Val(), err)
			}
			m.TelemetryConfig.FlushInterval = caddy.Duration(dur)
		case "buffer_size":
			if !d.NextArg() {
				return d.ArgErr()
			}
			sz, err := strconv.Atoi(d.Val())
			if err != nil || sz <= 0 {
				return d.Errf("invalid buffer_size: %s (%v)", d.Val(), err)
			}
			m.TelemetryConfig.BufferSize = sz
		case "retention":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid retention: %s (%v)", d.Val(), err)
			}
			m.TelemetryConfig.Retention = caddy.Duration(dur)
		case "alert":
			var ch AlertChannelSettings
			if !d.NextArg() {
				return d.ArgErr()
			}
			ch.Name = d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			ch.URL = d.Val()
			for d.NextBlock(2) {
				switch d.Val() {
				case "events", "event":
					ch.Events = append(ch.Events, d.RemainingArgs()...)
				case "cooldown":
					if !d.NextArg() {
						return d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return d.Errf("invalid alert cooldown: %s (%v)", d.Val(), err)
					}
					ch.Cooldown = caddy.Duration(dur)
				default:
					return d.Errf("unrecognized alert subdirective: %s", d.Val())
				}
			}
			m.TelemetryConfig.AlertChannels = append(m.TelemetryConfig.AlertChannels, ch)
		default:
			return d.Errf("unrecognized telemetry subdirective: %s", d.Val())
		}
	}
	return nil
}

func (m *Middleware) parseControl(d *caddyfile.Dispenser) error {
	if m.ControlConfig == nil {
		m.ControlConfig = new(ControlSettings)
	}
	for d.NextBlock(1) {
		switch d.Val() {
		case "db", "db_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ControlConfig.DBPath = d.Val()
		case "hmac_secret", "secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ControlConfig.HMACSecret = d.Val()
		default:
			return d.Errf("unrecognized control subdirective: %s", d.Val())
		}
	}
	return nil
}

func (m *Middleware) parseSidecar(d *caddyfile.Dispenser) error {
	if m.SidecarConfig == nil {
		m.SidecarConfig = new(SidecarSettings)
	}
	for d.NextBlock(1) {
		switch d.Val() {
		case "listen":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SidecarConfig.Listen = d.Val()
		case "max_body_size":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
			var sz int64
			var err error
			valUpper := strings.ToUpper(val)
			if strings.HasSuffix(valUpper, "MB") {
				mb, err := strconv.ParseInt(strings.TrimSuffix(valUpper, "MB"), 10, 64)
				if err != nil {
					return d.Errf("invalid max_body_size: %s (%v)", val, err)
				}
				sz = mb * 1024 * 1024
			} else if strings.HasSuffix(valUpper, "KB") {
				kb, err := strconv.ParseInt(strings.TrimSuffix(valUpper, "KB"), 10, 64)
				if err != nil {
					return d.Errf("invalid max_body_size: %s (%v)", val, err)
				}
				sz = kb * 1024
			} else {
				sz, err = strconv.ParseInt(val, 10, 64)
				if err != nil || sz <= 0 {
					return d.Errf("invalid max_body_size: %s (must be positive bytes or size e.g. 10MB)", val)
				}
			}
			m.SidecarConfig.MaxBodySize = sz
		default:
			return d.Errf("unrecognized sidecar subdirective: %s", d.Val())
		}
	}
	return nil
}
