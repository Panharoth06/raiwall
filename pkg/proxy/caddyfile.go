package proxy

import (
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/auth"
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
//	    bot_defense <defense|challenge|audit|off>
//	    pow_difficulty <int>
//	    clearance_ttl <duration>
//	    honeypot <bool>
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

			case "bot_defense":
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

			case "pow_difficulty":
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

			case "clearance_ttl":
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

			case "honeypot", "honeypot_trap":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val := d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
				var enabled bool
				switch strings.ToLower(val) {
				case "true", "on", "yes", "1", "enabled":
					enabled = true
				case "false", "off", "no", "0", "disabled":
					enabled = false
				default:
					return d.Errf("invalid honeypot value: %s (must be true/false/on/off)", val)
				}
				m.HoneypotTrap = &enabled

			case "rate_limit":
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

			case "waiting_room":
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
					default:
						return d.Errf("unrecognized waiting_room subdirective: %s", d.Val())
					}
				}

			case "exceptions":
				if m.ExceptionConfig == nil {
					m.ExceptionConfig = new(ExceptionSettings)
				}
				for d.NextBlock(1) {
					switch d.Val() {
					case "rule":
						args := d.RemainingArgs()
						if len(args) == 0 {
							return d.ArgErr()
						}
						ruleID := args[0]
						exRule := &acl.ExceptionRule{
							ID:     ruleID,
							RuleID: "*",
						}
						for d.NextBlock(2) {
							sub := d.Val()
							switch sub {
							case "description":
								descArgs := d.RemainingArgs()
								exRule.Description = strings.Join(descArgs, " ")
							case "host":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.Host = d.Val()
							case "path":
								if !d.NextArg() {
									return d.ArgErr()
								}
								val := d.Val()
								if strings.HasSuffix(val, "/*") && !strings.ContainsAny(val[:len(val)-2], "$()[]+?*^") {
									exRule.PathPrefix = strings.TrimSuffix(val, "/*")
								} else if strings.HasSuffix(val, "*") && !strings.ContainsAny(val[:len(val)-1], "$()[]+?*^") {
									exRule.PathPrefix = strings.TrimSuffix(val, "*")
								} else if strings.HasPrefix(val, "^") || strings.ContainsAny(val, "$()[]+?*") {
									exRule.PathRegex = val
								} else {
									exRule.PathPrefix = val
								}
							case "path_regex":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.PathRegex = d.Val()
							case "path_prefix":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.PathPrefix = d.Val()
							case "method":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.Method = d.Val()
							case "location":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.Location = d.Val()
							case "param", "param_name":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.ParamName = d.Val()
							case "param_regex":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.ParamRegex = d.Val()
							case "rule_id":
								if !d.NextArg() {
									return d.ArgErr()
								}
								exRule.RuleID = d.Val()
							default:
								return d.Errf("unrecognized exceptions rule property: %s", sub)
							}
						}
						m.ExceptionConfig.Rules = append(m.ExceptionConfig.Rules, exRule)
					default:
						return d.Errf("unrecognized exceptions subdirective: %s", d.Val())
					}
				}

			case "acl":
				if m.ACLConfig == nil {
					m.ACLConfig = new(ACLSettings)
				}
				for d.NextBlock(1) {
					switch d.Val() {
					case "threat_feed":
						args := d.RemainingArgs()
						if len(args) < 2 {
							return d.ArgErr()
						}
						if m.ACLConfig.ThreatFeeds == nil {
							m.ACLConfig.ThreatFeeds = make(map[string]string)
						}
						m.ACLConfig.ThreatFeeds[args[0]] = args[1]
					case "geoip_db", "geoip_country", "geoip_country_db":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.ACLConfig.GeoIPCountry = d.Val()
					case "geoip_asn", "geoip_asn_db":
						if !d.NextArg() {
							return d.ArgErr()
						}
						m.ACLConfig.GeoIPASN = d.Val()
					case "rule":
						args := d.RemainingArgs()
						if len(args) == 0 {
							return d.ArgErr()
						}
						ruleName := args[0]
						rule := &acl.ACLRule{
							Name:   ruleName,
							Action: acl.ActionBlock,
						}
						for d.NextBlock(2) {
							sub := d.Val()
							switch sub {
							case "expr", "expression":
								exprArgs := d.RemainingArgs()
								if len(exprArgs) == 0 {
									return d.ArgErr()
								}
								rule.Expression = strings.Join(exprArgs, " ")
							case "action":
								if !d.NextArg() {
									return d.ArgErr()
								}
								rule.Action = acl.Action(strings.ToLower(d.Val()))
							case "priority":
								if !d.NextArg() {
									return d.ArgErr()
								}
								pri, err := strconv.Atoi(d.Val())
								if err != nil {
									return d.Errf("invalid priority: %s", d.Val())
								}
								rule.Priority = pri
							case "status_code", "status":
								if !d.NextArg() {
									return d.ArgErr()
								}
								sc, err := strconv.Atoi(d.Val())
								if err != nil || sc < 200 || sc > 599 {
									return d.Errf("invalid status_code: %s", d.Val())
								}
								rule.StatusCode = sc
							case "redirect_url", "redirect":
								if !d.NextArg() {
									return d.ArgErr()
								}
								rule.RedirectURL = d.Val()
							default:
								return d.Errf("unrecognized acl rule property: %s", sub)
							}
						}
						m.ACLConfig.Rules = append(m.ACLConfig.Rules, rule)
					default:
						return d.Errf("unrecognized acl subdirective: %s", d.Val())
					}
				}

			case "auth":
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
					default:
						return d.Errf("unrecognized auth subdirective: %s", d.Val())
					}
				}

			default:
				return d.Errf("unrecognized raiwall subdirective: %s", d.Val())
			}
		}
	}

	return nil
}
