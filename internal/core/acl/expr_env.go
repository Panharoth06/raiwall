package acl

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

var (
	regexCache sync.Map // pattern string -> *regexp.Regexp
)

// EvalEnv defines the evaluation environment available within ACL expr expressions.
type EvalEnv struct {
	IP        string            `expr:"ip"`
	ClientIP  string            `expr:"client_ip"`
	JA4       string            `expr:"ja4"`
	Method    string            `expr:"method"`
	Path      string            `expr:"path"`
	Host      string            `expr:"host"`
	Headers   map[string]string `expr:"headers"`
	Cookies   map[string]string `expr:"cookies"`
	Query     map[string]string `expr:"query"`
	UserAgent string            `expr:"user_agent"`
	Geo       GeoData           `expr:"geo"`

	bartTable  *BARTTable
	ipGroupMgr *IPGroupManager
}

func cleanIPStr(s string) net.IP {
	return CleanIP(s)
}

// InCIDR checks if the provided IP belongs to a CIDR subnet.
func (e *EvalEnv) InCIDR(ipStr, cidr string) bool {
	ip := cleanIPStr(ipStr)
	if ip == nil {
		return false
	}
	return InCIDR(ip, cidr)
}

// InFeed checks if the provided IP belongs to a named BART threat feed.
func (e *EvalEnv) InFeed(ipStr, feedName string) bool {
	if e.bartTable == nil {
		return false
	}
	ip := cleanIPStr(ipStr)
	if ip == nil {
		return false
	}
	return e.bartTable.InFeed(ip, feedName)
}

// InIPGroup checks if the provided IP belongs to a named IP group.
func (e *EvalEnv) InIPGroup(ipStr, groupName string) bool {
	if e.ipGroupMgr != nil {
		return e.ipGroupMgr.InGroupStr(ipStr, groupName)
	}
	return e.InFeed(ipStr, groupName)
}

// IPGroup returns an IPGroupRef for expression evaluation.
func (e *EvalEnv) IPGroup(name string) IPGroupRef {
	return IPGroupRef{Name: name, manager: e.ipGroupMgr}
}

// HasPrefix reports whether s begins with prefix.
func (e *EvalEnv) HasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// Contains reports whether substr is within s.
func (e *EvalEnv) Contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// RegexMatch reports whether pattern matches s using cached compiled regular expressions.
func (e *EvalEnv) RegexMatch(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp).MatchString(s)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	regexCache.Store(pattern, re)
	return re.MatchString(s)
}

// BuildEvalEnv constructs an EvalEnv from an waf.RequestContext, GeoData, and optional BARTTable.
func BuildEvalEnv(reqCtx *waf.RequestContext, geo GeoData, bartTable *BARTTable) *EvalEnv {
	return BuildEvalEnvWithManager(reqCtx, geo, bartTable, nil)
}

// BuildEvalEnvWithManager constructs an EvalEnv with both BARTTable and IPGroupManager.
func BuildEvalEnvWithManager(reqCtx *waf.RequestContext, geo GeoData, bartTable *BARTTable, ipGroupMgr *IPGroupManager) *EvalEnv {
	env := &EvalEnv{
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
		Query:      make(map[string]string),
		Geo:        geo,
		bartTable:  bartTable,
		ipGroupMgr: ipGroupMgr,
	}
	env.Geo.Country_ = geo.Country
	env.Geo.Continent_ = geo.Continent
	env.Geo.ASN_ = geo.ASN
	env.Geo.ASOrg_ = geo.ASOrg

	if reqCtx == nil {
		return env
	}

	if reqCtx.ClientIP != nil {
		env.IP = reqCtx.ClientIP.String()
		env.ClientIP = env.IP
	}
	env.JA4 = reqCtx.JA4
	env.Method = reqCtx.Method
	env.Path = reqCtx.Path
	env.Host = reqCtx.Host
	env.UserAgent = reqCtx.UserAgent

	// Headers (case-insensitive keys stored lowercase)
	for k, v := range reqCtx.Headers {
		if len(v) > 0 {
			env.Headers[strings.ToLower(k)] = v[0]
		}
	}

	// Query parameters
	if reqCtx.Query != "" {
		if qValues, err := url.ParseQuery(reqCtx.Query); err == nil {
			for k, v := range qValues {
				if len(v) > 0 {
					env.Query[k] = v[0]
				}
			}
		}
	}

	// Cookies from Cookie header
	if cookieHeader := reqCtx.Headers.Get("Cookie"); cookieHeader != "" {
		header := http.Header{"Cookie": []string{cookieHeader}}
		req := &http.Request{Header: header}
		for _, c := range req.Cookies() {
			env.Cookies[c.Name] = c.Value
		}
	}

	return env
}

// evalInCIDR is a standalone function helper for expr compilation.
func evalInCIDR(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("in_cidr requires 2 arguments (ip, subnet)")
	}
	ipStr, ok1 := params[0].(string)
	cidr, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	ip := cleanIPStr(ipStr)
	if ip == nil {
		return false, nil
	}
	return InCIDR(ip, cidr), nil
}

// evalRegexMatch is a standalone function helper for expr compilation.
func evalRegexMatch(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("regex_match requires 2 arguments (pattern, str)")
	}
	pattern, ok1 := params[0].(string)
	s, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp).MatchString(s), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, nil
	}
	regexCache.Store(pattern, re)
	return re.MatchString(s), nil
}

// evalHasPrefix is a standalone function helper for expr compilation.
func evalHasPrefix(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("has_prefix requires 2 arguments (str, prefix)")
	}
	s, ok1 := params[0].(string)
	prefix, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	return strings.HasPrefix(s, prefix), nil
}
