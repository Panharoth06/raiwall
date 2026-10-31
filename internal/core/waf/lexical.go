package waf

import (
	"net/url"
	"strings"

	"github.com/corazawaf/libinjection-go"
)

// TriageResult designates the fast lexical classification of a candidate value.
type TriageResult int

const (
	TriageBenign TriageResult = iota
	TriageSuspectSQLi
	TriageSuspectXSS
	TriageSuspectCmdI
	TriageSuspectTraversal
)

func (r TriageResult) String() string {
	switch r {
	case TriageBenign:
		return "Benign"
	case TriageSuspectSQLi:
		return "SuspectSQLi"
	case TriageSuspectXSS:
		return "SuspectXSS"
	case TriageSuspectCmdI:
		return "SuspectCmdI"
	case TriageSuspectTraversal:
		return "SuspectTraversal"
	default:
		return "Unknown"
	}
}

// Shell metacharacters and common invocation tokens
const shellMetachars = ";|&`$><\n\r"

var shellBinaries = [...]string{
	"sh", "bash", "zsh", "dash", "ash", "csh", "tcsh", "ksh",
	"curl", "wget", "nc", "netcat", "ncat", "socat", "telnet",
	"python", "python3", "perl", "ruby", "php", "node", "lua",
	"cat", "more", "less", "head", "tail", "nl", "od",
	"chmod", "chown", "sudo", "su", "id", "whoami", "uname",
	"busybox", "exec", "eval", "system", "passthru", "touch", "rm",
	"sleep", "kill", "killall", "ping", "traceroute", "ifconfig", "ip",
	// Windows command interpreters and living-off-the-land binaries. These are
	// unambiguous enough to list without tripping ordinary parameter values.
	"cmd", "powershell", "pwsh", "certutil", "bitsadmin", "mshta",
	"rundll32", "regsvr32", "wmic", "schtasks", "cscript", "wscript",
	"netstat", "nslookup", "certreq",
}

var shellPaths = [...]string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts",
	"/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/", "/usr/sbin/",
	"/dev/tcp/", "/dev/udp/", "/dev/null", "/tmp/",
}

// ScanCmdI performs an ultra-fast (<1 µs) scan for shell injection metacharacters and invocation patterns.
func ScanCmdI(s string) (bool, string) {
	if len(s) == 0 {
		return false, ""
	}

	// 1. Fast-path check: do any shell metacharacters exist?
	if !strings.ContainsAny(s, shellMetachars) {
		return false, ""
	}

	lower := strings.ToLower(s)

	// 2. Command substitution: $(...), ${...}, or backticks
	if strings.Contains(s, "$(") {
		return true, "command substitution $(...)"
	}
	if strings.Contains(s, "${") {
		return true, "parameter expansion ${...}"
	}
	if strings.Contains(s, "`") {
		return true, "backtick execution `...`"
	}

	// 3. Suspicious system paths combined with metacharacters
	for _, p := range shellPaths {
		if strings.Contains(lower, p) {
			return true, "shell path reference: " + p
		}
	}

	// 4. Command chaining or piping (; , && , || , |)
	// Check if metacharacter is followed by or combined with known binaries
	hasChain := strings.Contains(s, ";") || strings.Contains(s, "&&") ||
		strings.Contains(s, "||") || strings.Contains(s, "|") ||
		strings.Contains(s, "&") || strings.Contains(s, "\n") ||
		strings.Contains(s, ">") || strings.Contains(s, "<")

	if hasChain {
		// Look for binary invocations
		for _, bin := range shellBinaries {
			// Look for binary as a word boundary
			idx := strings.Index(lower, bin)
			for idx != -1 {
				// Check boundary before: must be start, whitespace, or metachar
				validBefore := (idx == 0) || isCmdBoundary(lower[idx-1])
				// Check boundary after: must be end, whitespace, flag, slash, or metachar
				endIdx := idx + len(bin)
				validAfter := (endIdx == len(lower)) || isCmdBoundaryAfter(lower[endIdx])

				if validBefore && validAfter {
					return true, "shell command invocation: " + bin
				}

				// Find next occurrence
				nextIdx := strings.Index(lower[idx+1:], bin)
				if nextIdx == -1 {
					break
				}
				idx = idx + 1 + nextIdx
			}
		}
	}

	return false, ""
}

func isCmdBoundary(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' ||
		b == ';' || b == '|' || b == '&' || b == '`' || b == '$' ||
		b == '(' || b == ')' || b == '<' || b == '>' || b == '/' ||
		b == '\\' || b == '"' || b == '\''
}

// isCmdBoundaryAfter also accepts '.' so Windows executables referenced with
// an extension (curl.exe, powershell.exe) match their bare command name.
func isCmdBoundaryAfter(b byte) bool {
	return isCmdBoundary(b) || b == '.'
}

// Directory traversal sequence indicators
var traversalSequences = [...]string{
	"../", "..\\",
	"/..", "\\..",
	"..;", ";/", "/;",
	"..%2f", "..%2F", "..%5c", "..%5C",
	"%2e%2e/", "%2e%2e\\", "%2e%2e%2f", "%2e%2e%5c",
	".../", "..../", "...\\", "....\\",
}

// Sensitive system files and directories across Unix and Windows
var sensitivePaths = [...]string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
	"/etc/resolv.conf", "/etc/master.passwd", "/etc/sudoers", "/etc/crontab",
	"/proc/self/", "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
	"win.ini", "system.ini", "boot.ini",
	"windows/system32", "windows\\system32",
	"/var/log/",
	"/.env", "\\.env",
	"/.ssh/", "\\.ssh\\",
	".git/config", ".git/head",
	"id_rsa", "id_ed25519", "authorized_keys",
}

// Dangerous URI schemes used for local/remote inclusion attacks
var dangerousFileSchemes = [...]string{
	"php://", "file://", "phar://", "zip://", "data://",
}

// ScanPathTraversal checks for directory traversal sequences (../, ..\) and sensitive file references in < 1 µs.
func ScanPathTraversal(s string) (bool, string) {
	if len(s) < 2 {
		return false, ""
	}

	// Fast-path: must contain dot, slash, backslash, semicolon, or percent
	if !strings.ContainsAny(s, "./\\%;") {
		return false, ""
	}

	lower := strings.ToLower(s)

	// 1. Directory traversal sequences
	for _, seq := range traversalSequences {
		if strings.Contains(lower, seq) {
			return true, "directory traversal sequence: " + seq
		}
	}

	// 2. Sensitive system files and credential leaks
	for _, p := range sensitivePaths {
		if strings.Contains(lower, p) {
			return true, "sensitive file reference: " + p
		}
	}

	// 3. Dangerous URI schemes for LFI/RFI
	for _, scheme := range dangerousFileSchemes {
		if strings.Contains(lower, scheme) {
			return true, "dangerous inclusion scheme: " + scheme
		}
	}

	// 4. Null byte injection in file paths
	if strings.Contains(s, "\x00") || strings.Contains(lower, "%00") {
		if strings.ContainsAny(s, "/\\") {
			return true, "null byte poisoning in path"
		}
	}

	return false, ""
}

// hasSQLCommentBreakout reports whether a value closes a string literal and
// immediately starts SQL comment syntax. libinjection misses several of these
// shapes (admin'#, admin'-- followed only by whitespace), but bounded AST
// verification confirms them once the value reaches Stage 3.
//
// The quote must follow a word byte, ')' or ']' so prose where the quote
// follows whitespace (e.g. `the symbol '#'`) is not redirected.
func hasSQLCommentBreakout(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] != '\'' && v[i] != '"' {
			continue
		}
		if i > 0 && !canPrecedeSQLBreakout(v[i-1]) {
			continue
		}

		j := i + 1
		for j < len(v) && isInlineSpace(v[j]) {
			j++
		}
		if j >= len(v) {
			continue
		}

		switch {
		case v[j] == '#':
			// A quote right after '#' is a literal mention (e.g. `'#'`).
			if j+1 >= len(v) || (v[j+1] != '\'' && v[j+1] != '"') {
				return true
			}
		case v[j] == '/' && j+1 < len(v) && v[j+1] == '*':
			return true
		case v[j] == '-' && j+1 < len(v) && v[j+1] == '-':
			if startsSQLCommentTail(v[j+2:]) {
				return true
			}
		}
	}
	return false
}

// startsSQLCommentTail reports whether the text after `--` looks like a SQL
// comment terminus (end of value, whitespace only, or a non-word token).
// Prose such as "it's -- fine" is left alone.
func startsSQLCommentTail(tail string) bool {
	k := 0
	for k < len(tail) && isInlineSpace(tail[k]) {
		k++
	}
	if k >= len(tail) {
		return true
	}
	return !isWordByte(tail[k])
}

func canPrecedeSQLBreakout(b byte) bool {
	return isWordByte(b) || b == ')' || b == ']'
}

// hasSQLBooleanTautology reports whether the value starts with an
// expression-like token and contains a boolean operator followed by a boolean
// literal (1 or true, 'x' and false). libinjection does not fingerprint this
// shape; bounded AST verification confirms it in the unquoted context.
func hasSQLBooleanTautology(v string) bool {
	lower := strings.ToLower(v)

	for _, op := range [...]string{"or", "and", "xor"} {
		idx := 0
		for {
			pos := strings.Index(lower[idx:], op)
			if pos == -1 {
				break
			}
			pos += idx
			idx = pos + len(op)

			if pos > 0 && isWordByte(lower[pos-1]) {
				continue
			}
			after := pos + len(op)
			if after < len(lower) && isWordByte(lower[after]) {
				continue
			}
			if !startsExpressionLike(lower[:pos]) {
				continue
			}
			if hasBooleanLiteral(strings.TrimLeft(lower[after:], " \t\r\n")) {
				return true
			}
		}
	}
	return false
}

// startsExpressionLike reports whether the prefix before a boolean operator is
// an operand (number, quoted literal, or grouped expression) rather than prose.
func startsExpressionLike(prefix string) bool {
	trimmed := strings.TrimLeft(prefix, " \t\r\n")
	if trimmed == "" {
		return false
	}
	switch b := trimmed[0]; {
	case b >= '0' && b <= '9':
		return true
	case b == '\'' || b == '"' || b == '(' || b == ')' || b == '-' || b == '+':
		return true
	default:
		return false
	}
}

func hasBooleanLiteral(s string) bool {
	if strings.HasPrefix(s, "true") {
		return literalBoundary(s[4:])
	}
	if strings.HasPrefix(s, "false") {
		return literalBoundary(s[5:])
	}
	return false
}

func literalBoundary(s string) bool {
	return s == "" || !isWordByte(s[0])
}

// xssGateTags lists element names that can execute script or load attacker
// content. The gate only routes values to AST verification; XSSChop decides.
var xssGateTags = [...]string{
	"script", "iframe", "object", "embed", "applet", "svg", "math",
	"img", "video", "audio", "source", "body", "frameset", "frame",
	"meta", "link", "base", "form", "style", "xmp", "details", "marquee",
	"input", "textarea",
}

// looksLikeHTMLInjection reports whether a value contains markup that merits
// bounded HTML tokenization: a dangerous element name, srcdoc, or an event
// handler attribute. libinjection misses slash-separated attributes and
// srcdoc payloads; XSSChop confirms (or rejects) these shapes.
func looksLikeHTMLInjection(v string) bool {
	if !strings.ContainsAny(v, "<\"'=") {
		return false
	}

	lower := strings.ToLower(v)
	if strings.Contains(lower, "srcdoc=") || hasEventHandlerAttr(lower) {
		return true
	}

	for i := 0; i < len(lower); i++ {
		if lower[i] != '<' {
			continue
		}
		j := i + 1
		for j < len(lower) && (lower[j] == '/' || isInlineSpace(lower[j])) {
			j++
		}
		for _, tag := range xssGateTags {
			if !strings.HasPrefix(lower[j:], tag) {
				continue
			}
			end := j + len(tag)
			if end >= len(lower) || !isWordByte(lower[end]) {
				return true
			}
		}
	}
	return false
}

// hasEventHandlerAttr reports whether the value contains an on<name>= HTML
// event handler attribute (whitespace before '=' is tolerated).
func hasEventHandlerAttr(s string) bool {
	for i := 0; i+3 < len(s); i++ {
		if s[i] != 'o' || s[i+1] != 'n' {
			continue
		}
		if i > 0 && isWordByte(s[i-1]) {
			continue
		}
		j := i + 2
		start := j
		for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
			j++
		}
		if j == start {
			continue
		}
		for j < len(s) && isInlineSpace(s[j]) {
			j++
		}
		if j < len(s) && s[j] == '=' {
			return true
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

func isInlineSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// Triage classifies a normalized string into Benign, SuspectSQLi, SuspectXSS, or SuspectCmdI in < 2 µs.
func Triage(value string) TriageResult {
	res, _ := TriageWithDetails(value)
	return res
}

// TriageWithDetails returns the classification and corresponding fingerprint or reason.
func TriageWithDetails(value string) (TriageResult, string) {
	if len(value) == 0 {
		return TriageBenign, ""
	}

	// 1. Fast Shell Command Injection Scan (<1 µs)
	if isCmdI, reason := ScanCmdI(value); isCmdI {
		return TriageSuspectCmdI, reason
	}

	// 2. Fast SQL Injection Lexical Scan (<2 µs via pure-Go libinjection)
	if isSQLi, fingerprint := libinjection.IsSQLi(value); isSQLi {
		return TriageSuspectSQLi, fingerprint
	}

	// 2b. Structural breakouts that libinjection does not fingerprint:
	// comment closure (admin'#, admin'--) and expression-shaped boolean
	// tautologies (1 or true). Redirect to bounded AST verification instead
	// of letting the value pass as benign.
	if hasSQLCommentBreakout(value) {
		return TriageSuspectSQLi, "quote_comment_breakout"
	}
	if hasSQLBooleanTautology(value) {
		return TriageSuspectSQLi, "boolean_tautology"
	}

	// 3. Fast Cross-Site Scripting Lexical Scan (<2 µs via pure-Go libinjection and script pseudo-protocols)
	trimmed := strings.TrimSpace(value)
	lowerTrimmed := strings.ToLower(trimmed)
	if strings.HasPrefix(lowerTrimmed, "javascript:") ||
		strings.HasPrefix(lowerTrimmed, "vbscript:") ||
		strings.HasPrefix(lowerTrimmed, "data:text/html") {
		return TriageSuspectXSS, "script_pseudo_protocol"
	}

	if libinjection.IsXSS(value) {
		return TriageSuspectXSS, "libinjection_xss"
	}

	// 3b. Structural HTML injection that libinjection does not fingerprint
	// (<img/src=x/onerror=...>, <iframe srcdoc=...>). Route to bounded AST
	// verification instead of letting the value pass as benign.
	if looksLikeHTMLInjection(value) {
		return TriageSuspectXSS, "html_injection_shape"
	}

	// 4. Fast Path Traversal & LFI Scan (<1 µs)
	if isTraversal, reason := ScanPathTraversal(value); isTraversal {
		return TriageSuspectTraversal, reason
	}

	return TriageBenign, ""
}

// LexicalEngine performs ultra-fast lexical threat analysis using pure-Go libinjection and shell scanner.
type LexicalEngine struct{}

// NewLexicalEngine creates a new thread-safe pure-Go LexicalEngine.
func NewLexicalEngine() *LexicalEngine {
	return &LexicalEngine{}
}

// Name returns the identifier for this engine.
func (l *LexicalEngine) Name() string {
	return "libinjection-go"
}

// InspectRequest scans Path, Query, Headers, and Body for lexical injection tokens.
func (l *LexicalEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	if ctx == nil {
		return VerdictAllow, nil
	}

	// 1. Inspect Path
	if triage, reason := TriageWithDetails(ctx.Path); triage != TriageBenign {
		return l.verdictForTriage(triage, "PATH", ctx.Path, reason), nil
	}

	// 2. Inspect Raw Query & Parsed Query Parameters
	if ctx.Query != "" {
		if triage, reason := TriageWithDetails(ctx.Query); triage != TriageBenign {
			return l.verdictForTriage(triage, "QUERY", ctx.Query, reason), nil
		}

		if parsedQuery, err := url.ParseQuery(ctx.Query); err == nil {
			for key, values := range parsedQuery {
				for _, val := range values {
					if triage, reason := TriageWithDetails(val); triage != TriageBenign {
						return l.verdictForTriage(triage, "QUERY_PARAM ("+key+")", val, reason), nil
					}
				}
			}
		}
	}

	// 3. Inspect sensitive/custom headers (Cookies, Authorization, custom X- headers)
	for key, values := range ctx.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey == "cookie" || strings.HasPrefix(lowerKey, "x-") {
			for _, val := range values {
				if triage, reason := TriageWithDetails(val); triage != TriageBenign {
					return l.verdictForTriage(triage, "HEADER ("+key+")", val, reason), nil
				}
			}
		}
	}

	// 4. Inspect buffered body (if present)
	if len(ctx.Body) > 0 {
		bodyStr := string(ctx.Body)
		if triage, reason := TriageWithDetails(bodyStr); triage != TriageBenign {
			return l.verdictForTriage(triage, "BODY", bodyStr, reason), nil
		}
	}

	return VerdictAllow, nil
}

func (l *LexicalEngine) verdictForTriage(triage TriageResult, location string, val string, details string) *Verdict {
	switch triage {
	case TriageSuspectCmdI:
		ruleID := "CMDI_" + sanitizeRuleLocation(location)
		return &Verdict{
			Action: ActionBlock,
			RuleID: ruleID,
			Reason: "Command injection detected in " + location + ": " + details,
		}
	case TriageSuspectSQLi:
		ruleID := "SQLI_" + sanitizeRuleLocation(location)
		return &Verdict{
			Action: ActionBlock,
			RuleID: ruleID,
			Reason: "SQL injection detected in " + location + ": fingerprint " + details,
		}
	case TriageSuspectXSS:
		ruleID := "XSS_" + sanitizeRuleLocation(location)
		return &Verdict{
			Action: ActionBlock,
			RuleID: ruleID,
			Reason: "Cross-site scripting detected in " + location,
		}
	case TriageSuspectTraversal:
		ruleID := "TRAVERSAL_" + sanitizeRuleLocation(location)
		return &Verdict{
			Action: ActionBlock,
			RuleID: ruleID,
			Reason: "Path traversal / LFI attack detected in " + location + ": " + details,
		}
	default:
		return VerdictAllow
	}
}

func sanitizeRuleLocation(loc string) string {
	if strings.HasPrefix(loc, "QUERY_PARAM") {
		return "QUERY_PARAM"
	}
	if strings.HasPrefix(loc, "HEADER") {
		return "HEADER"
	}
	return loc
}

// InspectResponse evaluates the response context (passthrough for lexical triage stage).
func (l *LexicalEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	return VerdictAllow, nil
}
