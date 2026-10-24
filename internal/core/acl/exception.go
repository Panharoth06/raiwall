package acl

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

// ExceptionRule defines a granular false-positive suppression rule targeting
// a specific host, path, HTTP method, parameter location, parameter name, and WAF rule ID.
type ExceptionRule struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Host        string `json:"host,omitempty"`        // Exact, wildcard "*.domain.com", "*", or empty
	PathRegex   string `json:"path_regex,omitempty"`  // Path regex pattern
	PathPrefix  string `json:"path_prefix,omitempty"` // Path prefix pattern (faster alternative)
	Method      string `json:"method,omitempty"`      // HTTP method (GET, POST, "*", or empty)
	Location    string `json:"location,omitempty"`    // Parameter location (query, body, header, cookie, json, multipart, "*")
	ParamName   string `json:"param_name,omitempty"`  // Parameter name (exact, wildcard "*", or regex)
	ParamRegex  string `json:"param_regex,omitempty"` // Parameter name regex
	RuleID      string `json:"rule_id,omitempty"`     // Targeted WAF RuleID (e.g. "SEMANTIC_SQLI", "SEMANTIC_CMDI", "SEMANTIC_XSS", "*")

	compiledPathRegex  *regexp.Regexp
	compiledParamRegex *regexp.Regexp
}

// Compile precompiles regexes within the ExceptionRule.
func (r *ExceptionRule) Compile() error {
	if r.PathRegex != "" {
		re, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return fmt.Errorf("invalid path_regex %q in exception rule %q: %w", r.PathRegex, r.ID, err)
		}
		r.compiledPathRegex = re
	}
	if r.ParamRegex != "" {
		re, err := regexp.Compile(r.ParamRegex)
		if err != nil {
			return fmt.Errorf("invalid param_regex %q in exception rule %q: %w", r.ParamRegex, r.ID, err)
		}
		r.compiledParamRegex = re
	}
	return nil
}

func stripHostPort(host string) string {
	if host == "" || host == "*" {
		return host
	}
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

// Matches checks if the exception rule matches the request and parameter criteria.
func (r *ExceptionRule) Matches(host, path, method, location, paramName, ruleID string) bool {
	// 1. Host match
	if r.Host != "" && r.Host != "*" {
		cleanHost := stripHostPort(host)
		ruleHost := stripHostPort(r.Host)

		if strings.HasPrefix(ruleHost, "*.") {
			suffix := ruleHost[1:] // e.g. ".example.com"
			if !strings.HasSuffix(strings.ToLower(cleanHost), strings.ToLower(suffix)) &&
				!strings.EqualFold(cleanHost, ruleHost[2:]) {
				return false
			}
		} else if !strings.EqualFold(cleanHost, ruleHost) {
			return false
		}
	}

	// 2. Path match
	if r.PathPrefix != "" && !strings.HasPrefix(path, r.PathPrefix) {
		return false
	}
	if r.compiledPathRegex != nil && !r.compiledPathRegex.MatchString(path) {
		return false
	}

	// 3. Method match
	if r.Method != "" && r.Method != "*" {
		if !strings.EqualFold(r.Method, method) {
			return false
		}
	}

	// 4. Location match
	if r.Location != "" && r.Location != "*" {
		if !strings.EqualFold(r.Location, location) {
			if strings.EqualFold(r.Location, "body") && (strings.EqualFold(location, "json") || strings.EqualFold(location, "multipart")) {
				// JSON and Multipart payloads reside within the request body
			} else if (strings.EqualFold(r.Location, "header") && strings.EqualFold(location, "cookie")) ||
				(strings.EqualFold(r.Location, "cookie") && strings.EqualFold(location, "header")) {
				// Cookies reside within HTTP headers
			} else {
				return false
			}
		}
	}

	// 5. ParamName match
	if r.ParamRegex != "" && r.compiledParamRegex != nil {
		if !r.compiledParamRegex.MatchString(paramName) {
			return false
		}
	} else if r.ParamName != "" && r.ParamName != "*" {
		if strings.EqualFold(location, "header") || strings.EqualFold(location, "cookie") {
			if !strings.EqualFold(r.ParamName, paramName) {
				return false
			}
		} else {
			if r.ParamName != paramName {
				return false
			}
		}
	}

	// 6. RuleID match
	if r.RuleID != "" && r.RuleID != "*" {
		// Specific rule ID: does not match if caller is checking for blanket exemption (*),
		// or if the queried rule ID differs.
		if ruleID == "*" || !strings.EqualFold(r.RuleID, ruleID) {
			return false
		}
	}

	return true
}

// ExceptionEngine manages and evaluates parameter-level false-positive exceptions.
type ExceptionEngine struct {
	mu    sync.RWMutex
	rules []*ExceptionRule
}

// NewExceptionEngine constructs an ExceptionEngine with optional initial rules.
func NewExceptionEngine(rules ...*ExceptionRule) (*ExceptionEngine, error) {
	e := &ExceptionEngine{
		rules: make([]*ExceptionRule, 0, len(rules)),
	}
	for _, rule := range rules {
		if err := e.AddRule(rule); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// AddRule registers a new exception rule into the engine.
func (e *ExceptionEngine) AddRule(rule *ExceptionRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	if err := rule.Compile(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Update existing if matching ID
	if rule.ID != "" {
		for i, existing := range e.rules {
			if existing.ID == rule.ID {
				e.rules[i] = rule
				return nil
			}
		}
	}

	e.rules = append(e.rules, rule)
	return nil
}

// RemoveRule removes an exception rule by ID.
func (e *ExceptionEngine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, rule := range e.rules {
		if rule.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// ClearRules removes all rules from the engine.
func (e *ExceptionEngine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = e.rules[:0]
}

// Rules returns a copy of registered exception rules.
func (e *ExceptionEngine) Rules() []*ExceptionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*ExceptionRule, len(e.rules))
	copy(result, e.rules)
	return result
}

// Matches checks if any registered exception rule matches the given context.
func (e *ExceptionEngine) Matches(host, path, method, location, paramName, ruleID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if rule.Matches(host, path, method, location, paramName, ruleID) {
			return true
		}
	}
	return false
}

// MatchingRules returns all rules that match the given context.
func (e *ExceptionEngine) MatchingRules(host, path, method, location, paramName, ruleID string) []*ExceptionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []*ExceptionRule
	for _, rule := range e.rules {
		if rule.Matches(host, path, method, location, paramName, ruleID) {
			matched = append(matched, rule)
		}
	}
	return matched
}
