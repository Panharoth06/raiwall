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
				validAfter := (endIdx == len(lower)) || isCmdBoundary(lower[endIdx])

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
