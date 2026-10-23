package waf

import "fmt"

// Module identifies one of the 14 semantic detection modules
// (SafeLine v9.4.2 parity matrix).
type Module string

// The 14 semantic detection modules.
const (
	ModuleSQLInj      Module = "sql_inj"       // SQL Injection (AST: TiDB parser)
	ModuleXSS         Module = "xss"           // Cross-Site Scripting (AST: tdewolff)
	ModuleFileUpload  Module = "file_upload"   // Executable file uploads / webshell shells
	ModuleFileInclude Module = "file_include"  // LFI/RFI directory traversal & wrappers
	ModuleCmdInj      Module = "cmd_inj"       // Shell command injection (AST: mvdan/sh)
	ModuleJavaCodeInj Module = "java_code_inj" // OGNL / SpEL / Groovy expression injection
	ModuleJavaDeser   Module = "java_deserialization"
	ModulePHPDeser    Module = "php_deserialization"
	ModulePHPCodeInj  Module = "php_code_inj" // eval() / assert() / preg_replace /e
	ModuleASPCodeInj  Module = "asp_code_inj" // Classic ASP <% ... %> / ASP.NET markers
	ModuleSSTI        Module = "ssti"         // Jinja2 / Twig / Freemarker template injection
	ModuleCSRF        Module = "csrf"         // Origin/Referer validation on state-changing methods
	ModuleSSRF        Module = "ssrf"         // Cloud metadata / loopback URL fetch attempts
	ModuleMalHTTP     Module = "mal_http"     // Request smuggling / malformed HTTP markers
)

// NumModules is the fixed count of semantic detection modules.
const NumModules = 14

// ModuleMeta describes a semantic module for API consumers and the UI.
type ModuleMeta struct {
	Module      Module `json:"module"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// ModuleRegistry lists all modules with display metadata in canonical order.
var ModuleRegistry = []ModuleMeta{
	{ModuleSQLInj, "SQL Injection", "injection", "Detects SQL injection via libinjection triage and bounded SQL AST verification."},
	{ModuleXSS, "XSS", "injection", "Detects reflected and stored cross-site scripting payloads via bounded HTML/JS AST verification."},
	{ModuleFileUpload, "File Upload", "file", "Blocks executable file uploads and polyglot webshell attachments in multipart bodies."},
	{ModuleFileInclude, "File Inclusion", "file", "Detects LFI/RFI directory traversal, sensitive file access, and PHP stream wrappers."},
	{ModuleCmdInj, "Command Injection", "injection", "Detects OS command injection via shell metachar triage and bounded shell AST verification."},
	{ModuleJavaCodeInj, "Java Code Injection", "injection", "Detects OGNL, SpEL, and Groovy expression language gadgets."},
	{ModuleJavaDeser, "Java Deserialization", "injection", "Detects Java serialized magic bytes and gadget chains (Commons-Collections, Fastjson @type)."},
	{ModulePHPDeser, "PHP Deserialization", "injection", "Detects PHP serialized object payloads (O:8:\") and SET_TYPE gadget abuse."},
	{ModulePHPCodeInj, "PHP Code Injection", "injection", "Detects eval(), assert(), preg_replace /e and dynamic PHP execution markers."},
	{ModuleASPCodeInj, "ASP Code Injection", "injection", "Detects Classic ASP <% %> script tags and ASP.NET arbitrary execution markers."},
	{ModuleSSTI, "SSTI", "injection", "Detects server-side template injection syntax for Jinja2, Twig, and Freemarker."},
	{ModuleCSRF, "CSRF", "logic", "Validates Origin/Referer against Host on state-changing HTTP methods."},
	{ModuleSSRF, "SSRF", "logic", "Detects cloud metadata endpoints (169.254.169.254) and internal loopback fetch attempts."},
	{ModuleMalHTTP, "Malformed HTTP", "protocol", "Detects HTTP request smuggling: duplicate Content-Length and clashing Transfer-Encoding."},
}

// IsValidModule reports whether the given module identifier exists in the registry.
func IsValidModule(m Module) bool {
	for _, meta := range ModuleRegistry {
		if meta.Module == m {
			return true
		}
	}
	return false
}

// ModuleMode defines the operating sensitivity of a semantic module.
type ModuleMode uint8

// Supported module operating modes.
const (
	// ModeDisabled skips inspection for the module entirely.
	ModeDisabled ModuleMode = 0
	// ModeAudit records detections in telemetry without blocking.
	ModeAudit ModuleMode = 1
	// ModeBalance blocks confident matches and tolerates weak heuristics (default).
	ModeBalance ModuleMode = 2
	// ModeStrict blocks on any detection signal including low-confidence lexical hits.
	ModeStrict ModuleMode = 3
)

// String returns the lowercase identifier of the mode.
func (m ModuleMode) String() string {
	switch m {
	case ModeDisabled:
		return "disabled"
	case ModeAudit:
		return "audit"
	case ModeBalance:
		return "balance"
	case ModeStrict:
		return "strict"
	default:
		return "unknown"
	}
}

// MarshalJSON serializes the mode as its lowercase string name.
func (m ModuleMode) MarshalJSON() ([]byte, error) {
	return marshalSimpleString(string(m.String()))
}

// UnmarshalJSON accepts both string names ("balance") and legacy numeric values (2).
func (m *ModuleMode) UnmarshalJSON(data []byte) error {
	mode, err := unmarshalModuleMode(data)
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

// IsValidModuleMode reports whether the mode identifier is recognized.
func IsValidModuleMode(s string) bool {
	switch s {
	case "disabled", "audit", "balance", "strict":
		return true
	default:
		return false
	}
}

// ParseModuleModeString parses a plain-text mode identifier ("disabled", "audit", "balance", "strict").
func ParseModuleModeString(s string) (ModuleMode, error) {
	switch s {
	case "disabled":
		return ModeDisabled, nil
	case "audit":
		return ModeAudit, nil
	case "balance":
		return ModeBalance, nil
	case "strict":
		return ModeStrict, nil
	default:
		return ModeDisabled, fmt.Errorf("unknown module mode %q (expected disabled, audit, balance, or strict)", s)
	}
}

// SemanticMatrix is the resolved compilation of the 14 module modes.
// The array is indexed by the canonical module order and is immutable at runtime.
type SemanticMatrix [NumModules]ModuleMode

// ModuleIndex returns the canonical array index of a module, or -1 if unknown.
func ModuleIndex(m Module) int {
	for i, meta := range ModuleRegistry {
		if meta.Module == m {
			return i
		}
	}
	return -1
}

// DefaultMatrix returns the production-default matrix: every module on Balance.
func DefaultMatrix() SemanticMatrix {
	var sm SemanticMatrix
	for i := range sm {
		sm[i] = ModeBalance
	}
	return sm
}

// Mode returns the configured operating mode for the given module.
func (sm SemanticMatrix) Mode(m Module) ModuleMode {
	idx := ModuleIndex(m)
	if idx < 0 {
		return ModeBalance
	}
	return sm[idx]
}

// IsDisabled reports whether the module is skipped entirely.
func (sm SemanticMatrix) IsDisabled(m Module) bool {
	return sm.Mode(m) == ModeDisabled
}

// IsAudit reports whether detections for the module are recorded rather than enforced.
func (sm SemanticMatrix) IsAudit(m Module) bool {
	return sm.Mode(m) == ModeAudit
}

// IsStrict reports whether the module blocks on weak lexical signals too.
func (sm SemanticMatrix) IsStrict(m Module) bool {
	return sm.Mode(m) == ModeStrict
}

// IsEnabled reports whether the module inspects traffic at all.
func (sm SemanticMatrix) IsEnabled(m Module) bool {
	return sm.Mode(m) != ModeDisabled
}

// ApplyOverrides returns a copy of the matrix with the given module→mode overrides applied.
// Unknown modules in the map are ignored.
func (sm SemanticMatrix) ApplyOverrides(overrides map[Module]ModuleMode) SemanticMatrix {
	if len(overrides) == 0 {
		return sm
	}
	out := sm
	for m, mode := range overrides {
		if idx := ModuleIndex(m); idx >= 0 {
			out[idx] = mode
		}
	}
	return out
}

// MatrixSource resolves the effective SemanticMatrix for a given application ID.
// Applications without an explicit override inherit the global defaults.
type MatrixSource interface {
	MatrixFor(appID string) SemanticMatrix
}

// StaticMatrixSource serves a single fixed matrix for every application.
type StaticMatrixSource struct {
	Matrix SemanticMatrix
}

// MatrixFor returns the fixed matrix regardless of the app ID.
func (s StaticMatrixSource) MatrixFor(string) SemanticMatrix {
	return s.Matrix
}

// defaultMatrixPool is the zero-dependency fallback used when no source is wired.
var defaultMatrixPool = DefaultMatrix()

// matrixForApp resolves the effective matrix via the source, falling back to defaults.
func matrixForApp(src MatrixSource, appID string) SemanticMatrix {
	if src == nil {
		return defaultMatrixPool
	}
	if m := src.MatrixFor(appID); m != (SemanticMatrix{}) {
		return m
	}
	return defaultMatrixPool
}
