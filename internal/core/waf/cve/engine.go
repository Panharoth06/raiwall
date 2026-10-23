package cve

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
)

// Engine evaluates virtual-patch signatures with a fast method + URI-prefix
// index. Index buckets avoid scanning every rule: each request narrows to the
// method bucket (and the wildcard bucket) whose prefixes match the URI.
type Engine struct {
	base        []Signature
	index       atomic.Pointer[cveIndex]
	state       atomic.Pointer[RuleState]
	stateSource atomic.Pointer[StateSource]
}

// cveIndex precomputes lowercase tokens and the method-to-rule buckets once.
type cveIndex struct {
	// compiled per-rule match data, aligned with base slice order
	entry []compiledRule
	// buckets by method (upper) and "*" for any method
	buckets map[string][]int
}

// StateSource resolves runtime rule-state externally (e.g. from the atomic
// control-plane config snapshot). When installed it wins over local toggles.
type StateSource func() *RuleState

// SetStateSource installs an external state resolver; a nil return reverts
// to the locally stored toggle set.
func (e *Engine) SetStateSource(src StateSource) {
	if src == nil {
		e.stateSource.Store(nil)
		return
	}
	e.stateSource.Store(&src)
}

// currentState resolves the effective rule state (local or external source).
func (e *Engine) currentState() *RuleState {
	if src := e.stateSource.Load(); src != nil {
		if st := (*src)(); st != nil {
			return st
		}
	}
	return e.state.Load()
}

type compiledRule struct {
	sig     *Signature
	methods map[string]struct{}
	tokens  []compiledToken
}

type compiledToken struct {
	field  string
	header string
	token  string
}

// NewEngine builds the fast index around the supplied signature set.
func NewEngine(rules []Signature) (*Engine, error) {
	if err := validate(rules); err != nil {
		return nil, err
	}
	e := &Engine{base: rules}
	e.rebuild()
	return e, nil
}

func validate(rules []Signature) error {
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("cve rule with empty id")
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("cve rule id %q duplicated", r.ID)
		}
		seen[r.ID] = struct{}{}
		if len(r.Matches) == 0 {
			return fmt.Errorf("cve rule %q has no match tokens", r.ID)
		}
		for _, m := range r.Matches {
			if m.Token == "" {
				return fmt.Errorf("cve rule %q has empty token", r.ID)
			}
			switch m.Field {
			case FieldPath, FieldQuery, FieldBody, FieldHeader, FieldAny:
			default:
				return fmt.Errorf("cve rule %q has unsupported field %q", r.ID, m.Field)
			}
			if m.Field == FieldHeader && m.Header == "" {
				return fmt.Errorf("cve header rule %q missing header name", r.ID)
			}
		}
	}
	return nil
}

// rebuild compiles the lookup index; cheap enough to run per config swap.
func (e *Engine) rebuild() {
	idx := &cveIndex{
		entry:   make([]compiledRule, len(e.base)),
		buckets: make(map[string][]int, 8),
	}
	for i := range e.base {
		sig := &e.base[i]
		cr := compiledRule{sig: sig} // nil methods map = any method
		if len(sig.Methods) > 0 && sig.Methods[0] != "*" {
			cr.methods = make(map[string]struct{}, len(sig.Methods))
			for _, m := range sig.Methods {
				cr.methods[strings.ToUpper(m)] = struct{}{}
			}
		}
		cr.tokens = make([]compiledToken, len(sig.Matches))
		for j, cm := range sig.Matches {
			cr.tokens[j] = compiledToken{
				field:  cm.Field,
				header: cm.Header,
				token:  strings.ToLower(cm.Token),
			}
		}
		idx.entry[i] = cr

		bucket := "*"
		if len(sig.Methods) > 0 && sig.Methods[0] != "*" {
			for m := range cr.methods {
				bucket = m
			}
		}
		idx.buckets[bucket] = append(idx.buckets[bucket], i)
	}
	e.index.Store(idx)
}

// Rule returns the live signature for an ID, or nil.
func (e *Engine) Rule(id string) *Signature {
	for i := range e.base {
		if e.base[i].ID == id {
			return &e.base[i]
		}
	}
	return nil
}

// Rules returns the bundled signature library.
func (e *Engine) Rules() []Signature {
	return e.base
}

// DisabledIDs returns the IDs currently withheld at runtime.
func (e *Engine) DisabledIDs() []string {
	st := e.state.Load()
	if st == nil {
		return nil
	}
	out := make([]string, 0, len(st.Disabled))
	for id := range st.Disabled {
		out = append(out, id)
	}
	return out
}

// SetEnabled stores runtime enable/disable overrides atomically.
func (e *Engine) SetEnabled(disabled map[string]struct{}) {
	st := &RuleState{Disabled: make(map[string]struct{}, len(disabled))}
	for id := range disabled {
		st.Disabled[id] = struct{}{}
	}
	e.state.Store(st)
}

// Evaluate runs the fast path: narrow candidates by method bucket and URI
// prefix, then match compiled tokens across the pre-lowered request surfaces.
// Returns the first fired signature.
func (e *Engine) Evaluate(in *Input) (*Match, bool) {
	st := e.currentState()
	if st != nil && st.IsDisabled("*") {
		return nil, false // engine-wide disable
	}

	// Request surfaces are lowered once; path/query are small, the body view
	// is bounded (exploit signatures sit near the payload start in practice).
	lowerPath := strings.ToLower(in.Path)
	lowerQuery := strings.ToLower(in.RawQuery)
	lowerBody := compactLowerBody(in.Body)

	method := strings.ToUpper(in.Method)
	for _, bucket := range []string{method, "*"} {
		idx := e.index.Load()
		if idx == nil {
			return nil, false
		}
		if m, ok := idx.evaluateBucket(bucket, in, lowerPath, lowerQuery, lowerBody, st); ok {
			return m, true
		}
	}
	return nil, false
}

// compactLowerBody bounds body scanning to the first 64 KB: published exploit
// chains place their signature token near the payload start.
func compactLowerBody(body []byte) []byte {
	const maxScan = 64 * 1024
	if len(body) > maxScan {
		body = body[:maxScan]
	}
	return bytes.ToLower(body)
}

func (i *cveIndex) evaluateBucket(
	bucket string,
	in *Input,
	lowerPath, lowerQuery string,
	lowerBody []byte,
	st *RuleState,
) (*Match, bool) {
	for _, ri := range i.buckets[bucket] {
		cr := &i.entry[ri]
		if cr.methods != nil {
			if _, ok := cr.methods[in.Method]; !ok {
				continue
			}
		}
		if st.IsDisabled(cr.sig.ID) {
			continue
		}
		if m, ok := cr.match(in, lowerPath, lowerQuery, lowerBody); ok {
			return m, true
		}
	}
	return nil, false
}

func (c *compiledRule) match(in *Input, lowerPath, lowerQuery string, lowerBody []byte) (*Match, bool) {
	for _, tk := range c.tokens {
		switch tk.field {
		case FieldPath:
			if m, ok := c.contains(lowerPath, tk, "path"); ok {
				return m, true
			}
		case FieldQuery:
			if m, ok := c.contains(lowerQuery, tk, "query"); ok {
				return m, true
			}
		case FieldBody:
			if m, ok := c.containsBytes(lowerBody, tk); ok {
				return m, true
			}
		case FieldHeader:
			for key, vals := range in.Headers {
				if !strings.EqualFold(key, tk.header) {
					continue
				}
				for _, val := range vals {
					if strings.Contains(strings.ToLower(val), tk.token) {
						return c.fire(tk.token, FieldHeader, tk.header), true
					}
				}
			}
		default: // FieldAny: path, query, headers and body
			if m, ok := c.contains(lowerPath, tk, "path"); ok {
				return m, true
			}
			if m, ok := c.contains(lowerQuery, tk, "query"); ok {
				return m, true
			}
			if m, ok := c.containsBytes(lowerBody, tk); ok {
				return m, true
			}
			for key, vals := range in.Headers {
				for _, val := range vals {
					if strings.Contains(strings.ToLower(val), tk.token) {
						return c.fire(tk.token, FieldAny, key), true
					}
				}
			}
		}
	}
	return nil, false
}

func (c *compiledRule) contains(haystack string, tk compiledToken, field string) (*Match, bool) {
	if haystack != "" && strings.Contains(haystack, tk.token) {
		return c.fire(tk.token, field, ""), true
	}
	return nil, false
}

func (c *compiledRule) containsBytes(haystack []byte, tk compiledToken) (*Match, bool) {
	if len(haystack) > 0 && bytes.Contains(haystack, []byte(tk.token)) {
		return c.fire(tk.token, FieldBody, ""), true
	}
	return nil, false
}

// fire builds the fired Match handle for verdict plumbing.
func (c *compiledRule) fire(token, field, header string) *Match {
	return &Match{
		Rule:     c.sig,
		Token:    token,
		Field:    field,
		Header:   header,
		Category: c.sig.Category,
	}
}

// DecodePath resolves remaining percent-encoding in a path so that probes
// double-encoded upstream (CVE-2017-9805-style obfuscation) still match.
func DecodePath(raw string) string {
	d, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return d
}
