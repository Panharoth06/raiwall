package engine

import (
	"net/url"
	"strings"

	"github.com/corazawaf/libinjection-go"
)

// LexicalEngine performs ultra-fast lexical threat analysis using pure-Go libinjection.
// It detects SQL Injection (SQLi) and Cross-Site Scripting (XSS) with zero CGO dependencies.
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
	if isSQLi, fingerprint := libinjection.IsSQLi(ctx.Path); isSQLi {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SQLI_PATH",
			Reason: "SQL injection detected in request path: fingerprint " + fingerprint,
		}, nil
	}
	if libinjection.IsXSS(ctx.Path) {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "XSS_PATH",
			Reason: "Cross-site scripting (XSS) detected in request path",
		}, nil
	}

	// 2. Inspect Raw Query & Parsed Query Parameters
	if ctx.Query != "" {
		if isSQLi, fingerprint := libinjection.IsSQLi(ctx.Query); isSQLi {
			return &Verdict{
				Action: ActionBlock,
				RuleID: "SQLI_QUERY",
				Reason: "SQL injection detected in query string: fingerprint " + fingerprint,
			}, nil
		}
		if libinjection.IsXSS(ctx.Query) {
			return &Verdict{
				Action: ActionBlock,
				RuleID: "XSS_QUERY",
				Reason: "Cross-site scripting (XSS) detected in query string",
			}, nil
		}

		if parsedQuery, err := url.ParseQuery(ctx.Query); err == nil {
			for key, values := range parsedQuery {
				for _, val := range values {
					if isSQLi, fingerprint := libinjection.IsSQLi(val); isSQLi {
						return &Verdict{
							Action: ActionBlock,
							RuleID: "SQLI_QUERY_PARAM",
							Reason: "SQL injection detected in parameter " + key + ": fingerprint " + fingerprint,
						}, nil
					}
					if libinjection.IsXSS(val) {
						return &Verdict{
							Action: ActionBlock,
							RuleID: "XSS_QUERY_PARAM",
							Reason: "Cross-site scripting detected in parameter " + key,
						}, nil
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
				if isSQLi, fingerprint := libinjection.IsSQLi(val); isSQLi {
					return &Verdict{
						Action: ActionBlock,
						RuleID: "SQLI_HEADER",
						Reason: "SQL injection detected in header " + key + ": fingerprint " + fingerprint,
					}, nil
				}
				if libinjection.IsXSS(val) {
					return &Verdict{
						Action: ActionBlock,
						RuleID: "XSS_HEADER",
						Reason: "Cross-site scripting detected in header " + key,
					}, nil
				}
			}
		}
	}

	// 4. Inspect buffered body (if present)
	if len(ctx.Body) > 0 {
		bodyStr := string(ctx.Body)
		if isSQLi, fingerprint := libinjection.IsSQLi(bodyStr); isSQLi {
			return &Verdict{
				Action: ActionBlock,
				RuleID: "SQLI_BODY",
				Reason: "SQL injection detected in body: fingerprint " + fingerprint,
			}, nil
		}
		if libinjection.IsXSS(bodyStr) {
			return &Verdict{
				Action: ActionBlock,
				RuleID: "XSS_BODY",
				Reason: "Cross-site scripting detected in body",
			}, nil
		}
	}

	return VerdictAllow, nil
}

// InspectResponse evaluates the response context (passthrough for lexical triage stage).
func (l *LexicalEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	return VerdictAllow, nil
}
