package caddy

import (
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func (m *Middleware) parseExceptions(d *caddyfile.Dispenser) error {
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
	return nil
}

func (m *Middleware) parseACL(d *caddyfile.Dispenser) error {
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
	return nil
}
