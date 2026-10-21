package caddy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseRateLimit(d *caddyfile.Dispenser) error {
	if m.RateLimitConfig == nil {
		m.RateLimitConfig = new(RateLimitSettings)
	}
	for d.NextBlock(1) {
		switch d.Val() {
		case "tier1_velocity":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return d.ArgErr()
			}
			rateVal, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || rateVal <= 0 {
				return d.Errf("invalid tier1_velocity rate: %s", args[0])
			}
			winDur, err := caddy.ParseDuration(args[1])
			if err != nil {
				return d.Errf("invalid tier1_velocity window: %s", args[1])
			}
			m.RateLimitConfig.Tier1Rate = rateVal
			m.RateLimitConfig.Tier1Period = caddy.Duration(winDur)
			if len(args) >= 3 {
				burstVal, err := strconv.ParseInt(args[2], 10, 64)
				if err != nil || burstVal < 0 {
					return d.Errf("invalid tier1_velocity burst: %s", args[2])
				}
				m.RateLimitConfig.Tier1Burst = burstVal
			}
		case "tier2_attack":
			args := d.RemainingArgs()
			if len(args) < 3 {
				return d.ArgErr()
			}
			thresh, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || thresh <= 0 {
				return d.Errf("invalid tier2_attack threshold: %s", args[0])
			}
			winDur, err := caddy.ParseDuration(args[1])
			if err != nil {
				return d.Errf("invalid tier2_attack window: %s", args[1])
			}
			banDur, err := caddy.ParseDuration(args[2])
			if err != nil {
				return d.Errf("invalid tier2_attack ban_ttl: %s", args[2])
			}
			m.RateLimitConfig.Tier2Threshold = thresh
			m.RateLimitConfig.Tier2Window = caddy.Duration(winDur)
			m.RateLimitConfig.Tier2BanDuration = caddy.Duration(banDur)
		case "tier3_scanner":
			args := d.RemainingArgs()
			if len(args) < 3 {
				return d.ArgErr()
			}
			thresh, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || thresh <= 0 {
				return d.Errf("invalid tier3_scanner threshold: %s", args[0])
			}
			winDur, err := caddy.ParseDuration(args[1])
			if err != nil {
				return d.Errf("invalid tier3_scanner window: %s", args[1])
			}
			banDur, err := caddy.ParseDuration(args[2])
			if err != nil {
				return d.Errf("invalid tier3_scanner ban_ttl: %s", args[2])
			}
			m.RateLimitConfig.Tier3Threshold = thresh
			m.RateLimitConfig.Tier3Window = caddy.Duration(winDur)
			m.RateLimitConfig.Tier3BanDuration = caddy.Duration(banDur)
		case "storage":
			args := d.RemainingArgs()
			if len(args) < 1 {
				return d.ArgErr()
			}
			m.RateLimitConfig.StorageType = args[0]
			if len(args) >= 2 {
				m.RateLimitConfig.StorageAddr = args[1]
			}
		default:
			return d.Errf("unrecognized rate_limit subdirective: %s", d.Val())
		}
	}
	return nil
}

func (m *Middleware) parseWaitingRoom(d *caddyfile.Dispenser) error {
	if m.WaitingRoomConfig == nil {
		m.WaitingRoomConfig = new(WaitingRoomSettings)
	}
	m.WaitingRoomConfig.Enabled = true
	for d.NextBlock(1) {
		switch d.Val() {
		case "max_concurrent":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.ParseInt(d.Val(), 10, 64)
			if err != nil || val <= 0 {
				return d.Errf("invalid max_concurrent: %s", d.Val())
			}
			m.WaitingRoomConfig.MaxConcurrentInFlight = val
		case "max_queue_depth":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.ParseInt(d.Val(), 10, 64)
			if err != nil || val <= 0 {
				return d.Errf("invalid max_queue_depth: %s", d.Val())
			}
			m.WaitingRoomConfig.MaxQueueDepth = val
		case "admission_rate":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.ParseInt(d.Val(), 10, 64)
			if err != nil || val <= 0 {
				return d.Errf("invalid admission_rate: %s", d.Val())
			}
			m.WaitingRoomConfig.AdmissionRate = val
		case "admission_token_ttl", "token_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid admission_token_ttl: %s (%v)", d.Val(), err)
			}
			m.WaitingRoomConfig.AdmissionTokenTTL = caddy.Duration(dur)
		case "target_paths", "paths":
			for d.NextArg() {
				m.WaitingRoomConfig.TargetPaths = append(m.WaitingRoomConfig.TargetPaths, d.Val())
			}
		default:
			return d.Errf("unrecognized waiting_room subdirective: %s", d.Val())
		}
	}
	return nil
}
