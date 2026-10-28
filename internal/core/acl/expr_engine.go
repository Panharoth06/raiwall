package acl

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/expr-lang/expr/vm"
)

// ACLEngine manages a collection of compiled bytecode rules evaluated in priority order.
type ACLEngine struct {
	mu         sync.RWMutex
	rules      []*ACLRule
	bartTable  *BARTTable
	ipGroupMgr *IPGroupManager
	geoReader  GeoIPPort
	envPool    sync.Pool
}

// NewACLEngine constructs an initialized ACLEngine with optional initial rules.
func NewACLEngine(bartTable *BARTTable, geoReader GeoIPPort, rules ...*ACLRule) (*ACLEngine, error) {
	if bartTable == nil {
		bartTable = NewBARTTable()
	}
	e := &ACLEngine{
		bartTable:  bartTable,
		ipGroupMgr: NewIPGroupManager(bartTable),
		geoReader:  geoReader,
		rules:      make([]*ACLRule, 0, len(rules)),
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

// IPGroupManager returns the underlying IPGroupManager.
func (e *ACLEngine) IPGroupManager() *IPGroupManager {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ipGroupMgr
}

// SetIPGroupManager updates the IPGroupManager reference in ACLEngine and recompiles rules.
func (e *ACLEngine) SetIPGroupManager(mgr *IPGroupManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipGroupMgr = mgr
	if mgr != nil && mgr.Table() != nil {
		e.bartTable = mgr.Table()
	}
	for _, r := range e.rules {
		_ = r.CompileWithProviders(func() *BARTTable { return e.bartTable }, func() *IPGroupManager { return e.ipGroupMgr })
	}
}

// SetBARTTable updates the BARTTable reference in ACLEngine and recompiles rules.
func (e *ACLEngine) SetBARTTable(bt *BARTTable) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bartTable = bt
	if e.ipGroupMgr == nil {
		e.ipGroupMgr = NewIPGroupManager(bt)
	}
	for _, r := range e.rules {
		_ = r.CompileWithProviders(func() *BARTTable { return e.bartTable }, func() *IPGroupManager { return e.ipGroupMgr })
	}
}

// SetGeoIPReader updates the GeoIPReader reference in ACLEngine.
func (e *ACLEngine) SetGeoIPReader(r GeoIPPort) {
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
	ipGroupProvider := func() *IPGroupManager {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.ipGroupMgr
	}
	if err := rule.CompileWithProviders(provider, ipGroupProvider); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

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
func (e *ACLEngine) Evaluate(reqCtx *waf.RequestContext, geo GeoData) (*ACLVerdict, error) {
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
				Matched:            true,
				RuleName:           rule.Name,
				Action:             rule.Action,
				StatusCode:         rule.StatusCode,
				RedirectURL:        rule.RedirectURL,
				Reason:             fmt.Sprintf("ACL rule %q matched", rule.Name),
				ContinueInspection: rule.ContinueInspection,
			}, nil
		}
	}

	return &ACLVerdict{Matched: false, Action: ActionAllow}, nil
}

// EvaluateRequest automatically extracts GeoData from configured geoReader and evaluates rules.
func (e *ACLEngine) EvaluateRequest(reqCtx *waf.RequestContext) (*ACLVerdict, error) {
	var geo GeoData
	if e.geoReader != nil && reqCtx != nil && reqCtx.ClientIP != nil {
		geo = e.geoReader.Lookup(reqCtx.ClientIP)
	}
	return e.Evaluate(reqCtx, geo)
}

func (e *ACLEngine) acquireEnv(reqCtx *waf.RequestContext, geo GeoData) *EvalEnv {
	env := e.envPool.Get().(*EvalEnv)
	env.Geo = geo
	env.Geo.Country_ = geo.Country
	env.Geo.Continent_ = geo.Continent
	env.Geo.ASN_ = geo.ASN
	env.Geo.ASOrg_ = geo.ASOrg
	env.bartTable = e.bartTable
	env.ipGroupMgr = e.ipGroupMgr

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
		env.bartTable = nil
		env.ipGroupMgr = nil
		e.envPool.Put(env)
	}
}
