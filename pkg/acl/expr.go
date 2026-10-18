package acl

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/Panharoth06/raiwall/pkg/engine"
)

// ACLRule represents an access control policy evaluated via compiled bytecode.
type ACLRule struct {
	Name        string `json:"name"`
	Expression  string `json:"expression"`
	Action      Action `json:"action"` // allow, block, challenge, redirect, audit
	Priority    int    `json:"priority"`
	StatusCode  int    `json:"status_code,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`

	compiled      *vm.Program
	tableProvider func() *BARTTable
}

// CompileWithProvider compiles the rule expression into bytecode using expr with a dynamic BARTTable provider.
func (r *ACLRule) CompileWithProvider(provider func() *BARTTable) error {
	r.tableProvider = provider
	if strings.TrimSpace(r.Expression) == "" {
		return fmt.Errorf("empty expression for ACL rule %q", r.Name)
	}

	options := []expr.Option{
		expr.Env(&EvalEnv{}),
		expr.AsBool(),
		expr.Function("in_cidr", evalInCIDR, func(string, string) bool { return false }),
		expr.Function("regex_match", evalRegexMatch, func(string, string) bool { return false }),
		expr.Function("has_prefix", evalHasPrefix, func(string, string) bool { return false }),
		expr.Function("str_contains", evalContains, func(string, string) bool { return false }),
		expr.Function("in_feed", func(params ...any) (any, error) {
			if len(params) != 2 {
				return false, fmt.Errorf("in_feed requires 2 arguments (ip, feedName)")
			}
			ipStr, ok1 := params[0].(string)
			feed, ok2 := params[1].(string)
			if !ok1 || !ok2 {
				return false, nil
			}
			var bt *BARTTable
			if provider != nil {
				bt = provider()
			}
			if bt == nil {
				return false, nil
			}
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip == nil {
				return false, nil
			}
			return bt.InFeed(ip, feed), nil
		}, func(string, string) bool { return false }),
	}

	prog, err := expr.Compile(r.Expression, options...)
	if err != nil {
		return fmt.Errorf("compile ACL rule %q (%q): %w", r.Name, r.Expression, err)
	}

	r.compiled = prog

	// Default status codes
	if r.Action == ActionBlock && r.StatusCode == 0 {
		r.StatusCode = http.StatusForbidden
	}
	if r.Action == ActionRedirect && r.StatusCode == 0 {
		r.StatusCode = http.StatusFound
	}

	return nil
}

// Compile compiles the rule expression into bytecode using expr.
func (r *ACLRule) Compile(bartTable *BARTTable) error {
	return r.CompileWithProvider(func() *BARTTable { return bartTable })
}

// evalContains is a helper for expr.
func evalContains(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("contains requires 2 arguments (str, substr)")
	}
	s, ok1 := params[0].(string)
	sub, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	return strings.Contains(s, sub), nil
}

// ACLEngine executes ordered boolean ACL rules compiled to bytecode.
type ACLEngine struct {
	mu        sync.RWMutex
	rules     []*ACLRule
	bartTable *BARTTable
	geoReader *GeoIPReader
	envPool   sync.Pool
}

// NewACLEngine constructs an initialized ACLEngine with optional initial rules.
func NewACLEngine(bartTable *BARTTable, geoReader *GeoIPReader, rules ...*ACLRule) (*ACLEngine, error) {
	e := &ACLEngine{
		bartTable: bartTable,
		geoReader: geoReader,
		rules:     make([]*ACLRule, 0, len(rules)),
	}
	e.envPool.New = func() any {
		return &EvalEnv{
			Headers: make(map[string]string, 16),
			Cookies: make(map[string]string, 8),
			Query:   make(map[string]string, 8),
		}
	}

	for _, rule := range rules {
		if err := e.AddRule(rule); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// SetBARTTable updates the BARTTable reference in ACLEngine and recompiles rules.
func (e *ACLEngine) SetBARTTable(bt *BARTTable) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bartTable = bt
	for _, r := range e.rules {
		_ = r.Compile(bt)
	}
}

// SetGeoIPReader updates the GeoIPReader reference in ACLEngine.
func (e *ACLEngine) SetGeoIPReader(r *GeoIPReader) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoReader = r
}

// AddRule compiles and registers an ACLRule in priority order.
func (e *ACLEngine) AddRule(rule *ACLRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	provider := func() *BARTTable {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.bartTable
	}
	if err := rule.CompileWithProvider(provider); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Update if rule with same name exists
	updated := false
	for i, existing := range e.rules {
		if existing.Name == rule.Name {
			e.rules[i] = rule
			updated = true
			break
		}
	}
	if !updated {
		e.rules = append(e.rules, rule)
	}

	// Sort rules: lower Priority value evaluated first
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})

	return nil
}

// RemoveRule removes an ACL rule by name.
func (e *ACLEngine) RemoveRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, r := range e.rules {
		if r.Name == name {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// ClearRules removes all registered ACL rules.
func (e *ACLEngine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = e.rules[:0]
}

// Rules returns a snapshot of active rules.
func (e *ACLEngine) Rules() []*ACLRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	res := make([]*ACLRule, len(e.rules))
	copy(res, e.rules)
	return res
}

// Evaluate evaluates rules against request context and geo data with first-match-wins order.
func (e *ACLEngine) Evaluate(reqCtx *engine.RequestContext, geo GeoData) (*ACLVerdict, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.rules) == 0 {
		return &ACLVerdict{Matched: false, Action: ActionAllow}, nil
	}

	env := e.acquireEnv(reqCtx, geo)
	defer e.releaseEnv(env)

	for _, rule := range e.rules {
		if rule.compiled == nil {
			continue
		}

		out, err := vm.Run(rule.compiled, env)
		if err != nil {
			return nil, fmt.Errorf("evaluating ACL rule %q: %w", rule.Name, err)
		}

		matched, ok := out.(bool)
		if ok && matched {
			return &ACLVerdict{
				Matched:     true,
				RuleName:    rule.Name,
				Action:      rule.Action,
				StatusCode:  rule.StatusCode,
				RedirectURL: rule.RedirectURL,
				Reason:      fmt.Sprintf("ACL rule %q matched", rule.Name),
			}, nil
		}
	}

	return &ACLVerdict{Matched: false, Action: ActionAllow}, nil
}

// EvaluateRequest automatically extracts GeoData from configured geoReader and evaluates rules.
func (e *ACLEngine) EvaluateRequest(reqCtx *engine.RequestContext) (*ACLVerdict, error) {
	var geo GeoData
	if e.geoReader != nil && reqCtx != nil && reqCtx.ClientIP != nil {
		geo = e.geoReader.Lookup(reqCtx.ClientIP)
	}
	return e.Evaluate(reqCtx, geo)
}

func (e *ACLEngine) acquireEnv(reqCtx *engine.RequestContext, geo GeoData) *EvalEnv {
	env := e.envPool.Get().(*EvalEnv)
	env.Geo = geo
	env.Geo.Country_ = geo.Country
	env.Geo.Continent_ = geo.Continent
	env.Geo.ASN_ = geo.ASN
	env.Geo.ASOrg_ = geo.ASOrg
	env.bartTable = e.bartTable

	// Reset maps
	for k := range env.Headers {
		delete(env.Headers, k)
	}
	for k := range env.Cookies {
		delete(env.Cookies, k)
	}
	for k := range env.Query {
		delete(env.Query, k)
	}

	if reqCtx != nil {
		if reqCtx.ClientIP != nil {
			env.IP = reqCtx.ClientIP.String()
			env.ClientIP = env.IP
		} else {
			env.IP = ""
			env.ClientIP = ""
		}
		env.JA4 = reqCtx.JA4
		env.Method = reqCtx.Method
		env.Path = reqCtx.Path
		env.Host = reqCtx.Host
		env.UserAgent = reqCtx.UserAgent

		for k, v := range reqCtx.Headers {
			if len(v) > 0 {
				env.Headers[strings.ToLower(k)] = v[0]
			}
		}

		if reqCtx.Query != "" {
			parts := strings.Split(reqCtx.Query, "&")
			for _, part := range parts {
				k := part
				v := ""
				if eqIdx := strings.IndexByte(part, '='); eqIdx != -1 {
					k = part[:eqIdx]
					v = part[eqIdx+1:]
				}
				if unescapedK, err := url.QueryUnescape(k); err == nil {
					k = unescapedK
				}
				if unescapedV, err := url.QueryUnescape(v); err == nil {
					v = unescapedV
				}
				if k != "" {
					if _, exists := env.Query[k]; !exists {
						env.Query[k] = v
					}
				}
			}
		}

		if cookieHeader := reqCtx.Headers.Get("Cookie"); cookieHeader != "" {
			parts := strings.Split(cookieHeader, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if eqIdx := strings.IndexByte(part, '='); eqIdx != -1 {
					env.Cookies[part[:eqIdx]] = part[eqIdx+1:]
				}
			}
		}
	} else {
		env.IP = ""
		env.JA4 = ""
		env.Method = ""
		env.Path = ""
		env.Host = ""
		env.UserAgent = ""
	}

	return env
}

func (e *ACLEngine) releaseEnv(env *EvalEnv) {
	if env != nil {
		e.envPool.Put(env)
	}
}
