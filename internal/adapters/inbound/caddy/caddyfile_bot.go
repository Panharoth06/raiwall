package caddy

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseBotDefense(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	val := strings.ToLower(d.Val())
	switch val {
	case "defense", "challenge", "strict", "audit", "off", "disabled":
		m.BotDefense = val
	default:
		return d.Errf("invalid bot_defense: %s (must be defense, challenge, strict, audit, or off)", d.Val())
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

func (m *Middleware) parsePoWDifficulty(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	diff, err := strconv.ParseInt(d.Val(), 10, 64)
	if err != nil || diff <= 0 {
		return d.Errf("invalid pow_difficulty: %s (must be a positive integer)", d.Val())
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	m.PoWDifficulty = diff
	return nil
}

func (m *Middleware) parseClearanceTTL(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return d.Errf("invalid clearance_ttl: %s (%v)", d.Val(), err)
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	m.ClearanceTTL = caddy.Duration(dur)
	return nil
}

func (m *Middleware) parseHoneypot(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	val := strings.ToLower(d.Val())
	switch val {
	case "true", "on", "yes", "1", "enabled":
		enabled := true
		m.HoneypotTrap = &enabled
	case "false", "off", "no", "0", "disabled":
		enabled := false
		m.HoneypotTrap = &enabled
	default:
		return d.Errf("invalid honeypot value: %s (must be true or false)", d.Val())
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}
