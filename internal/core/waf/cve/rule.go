// Package cve implements the virtual-patching engine: a curated library of
// CVE exploit signatures evaluated with a fast method + URI-prefix index.
// Signatures are matched as case-insensitive tokens across request path,
// query, headers and body, one exploit stage per rule.
package cve

// Rule field targets for signature tokens.
const (
	FieldPath   = "path"
	FieldQuery  = "query"
	FieldBody   = "body"
	FieldHeader = "header"
	FieldAny    = "any"
)

// Signature is one virtual patch: a stable identifier (CVE id or an honest
// family id for non-CVE exposures), a URI prefix scope, and token matches.
type Signature struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	// Methods restricts evaluation; empty or "*" means every method.
	Methods []string `json:"methods,omitempty"`
	// Prefix scopes the rule to URI prefixes; "/" matches everything.
	Prefix  string     `json:"prefix,omitempty"`
	Matches []TokenRef `json:"matches"`
}

// TokenRef is a single exploit signature token.
// For FieldHeader only, Header designates the header name to scan.
type TokenRef struct {
	Field  string `json:"field"`
	Token  string `json:"token"`
	Header string `json:"header,omitempty"`
}

// Match is the evaluation result for a fired rule.
type Match struct {
	Rule     *Signature
	Token    string
	Field    string
	Header   string
	Category string
}

// Input is the request-shaped data the engine evaluates. Defined locally to
// avoid a dependency on the parent waf package.
type Input struct {
	Method   string
	Path     string // decoded request path
	RawQuery string // raw (still-encoded) query string
	Headers  map[string][]string
	Body     []byte
}

// RuleState holds per-rule enable/disable overrides keyed by rule ID.
// Read-only at evaluation time via atomic snapshot semantics.
type RuleState struct {
	Disabled map[string]struct{}
}

// IsDisabled reports whether the rule is withheld at runtime.
func (s *RuleState) IsDisabled(id string) bool {
	if s == nil {
		return false
	}
	_, ok := s.Disabled[id]
	return ok
}

// Categories of virtual patches (grouping for UI and batch toggles).
const (
	CatRCE             = "rce"
	CatAuthBypass      = "auth-bypass"
	CatInfoDisclosure  = "info-disclosure"
	CatDeserialization = "deserialization"
	CatInjection       = "injection"
	CatSSRF            = "ssrf"
	CatFileInclusion   = "file-inclusion"
	CatDoS             = "dos"
)
