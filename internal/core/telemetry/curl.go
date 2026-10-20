package telemetry

import (
	"fmt"
	"sort"
	"strings"
)

// GenerateCurlCommand constructs an executable, reproducible curl command from a ForensicEvent.
func GenerateCurlCommand(e *ForensicEvent) string {
	if e == nil {
		return ""
	}

	var parts []string
	parts = append(parts, "curl")

	// 1. Method
	method := strings.ToUpper(e.Method)
	if method == "" {
		method = "GET"
	}
	parts = append(parts, fmt.Sprintf("-X %s", method))

	// 2. URL
	scheme := "http"
	if strings.HasSuffix(e.Host, ":443") {
		scheme = "https"
	}
	path := e.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, e.Host, path)
	parts = append(parts, fmt.Sprintf("'%s'", escapeSingleQuote(fullURL)))

	// 3. Headers & Cookies
	if len(e.Headers) > 0 {
		var keys []string
		for k := range e.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			val := e.Headers[k]
			if strings.EqualFold(k, "Cookie") {
				parts = append(parts, fmt.Sprintf("-b '%s'", escapeSingleQuote(val)))
			} else {
				parts = append(parts, fmt.Sprintf("-H '%s: %s'", k, escapeSingleQuote(val)))
			}
		}
	}

	// 4. Request Body
	if e.TruncatedPayload != "" {
		parts = append(parts, fmt.Sprintf("--data-raw '%s'", escapeSingleQuote(e.TruncatedPayload)))
	}

	return strings.Join(parts, " ")
}

// escapeSingleQuote escapes single quotes for safe shell execution in single-quoted strings: ' -> '\''
func escapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}
