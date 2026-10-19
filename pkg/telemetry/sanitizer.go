package telemetry

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// RedactedValue is the placeholder used for sensitive data.
	RedactedValue = "[REDACTED]"

	// MaxPayloadBytes is the hard cap (2 KB) on raw payload snippets.
	MaxPayloadBytes = 2048
)

// Sanitizer cleanses sensitive headers, query parameters, payload bodies, and secrets
// in compliance with PCI-DSS 4.0 and data privacy guidelines.
type Sanitizer struct {
	sensitiveHeaderPrefixes []string
	sensitiveHeaderExact    map[string]struct{}
	sensitiveKeyPattern     *regexp.Regexp
	cardPattern             *regexp.Regexp
	jwtPattern              *regexp.Regexp
	bearerPattern           *regexp.Regexp
	jsonKeyPattern          *regexp.Regexp
	formKeyPattern          *regexp.Regexp
}

// DefaultSanitizer is the default singleton sanitizer instance.
var DefaultSanitizer = NewSanitizer()

// NewSanitizer constructs a configured Sanitizer.
func NewSanitizer() *Sanitizer {
	exactHeaders := map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
		"x-api-key":           {},
		"api-key":             {},
	}

	headerPrefixes := []string{
		"x-auth-",
		"x-api-",
	}

	// Sensitive keys: password, token, secret, cvv, card, api_key (and variations)
	keyRegex := `(?i)^(password|passwd|token|secret|cvv|cvc|card|credit_card|api_key|apikey|api-key|access_token|access-token|refresh_token|refresh-token|auth|auth_token|auth-token)$`

	// Match JSON key-value pairs: "key": "value" or "key": 1234
	jsonKeyRegex := `(?i)("(?:[a-zA-Z0-9_-]*?(?:password|token|secret|cvv|card|api_key|apikey|api-key|access_token|access-token|refresh_token|refresh-token)[a-zA-Z0-9_-]*?)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|[0-9.]+|true|false|null)`

	// Match Form/Query key-value pairs: key=value
	formKeyRegex := `(?i)((?:^|[&?])(?:[^=&?]*?(?:password|token|secret|cvv|card|api_key|apikey|api-key|access_token|access-token|refresh_token|refresh-token)[^=&?]*?)=)([^&]*)`

	// 13 to 19 digit card numbers: formatted 16-digit, 15-digit Amex, or contiguous digits
	cardRegex := `(?:\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|\b\d{4}[ -]?\d{6}[ -]?\d{5}\b|\b\d{13,19}\b)`

	// JWT token: header.payload.signature
	jwtRegex := `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b`

	// Bearer token
	bearerRegex := `(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`

	return &Sanitizer{
		sensitiveHeaderPrefixes: headerPrefixes,
		sensitiveHeaderExact:    exactHeaders,
		sensitiveKeyPattern:     regexp.MustCompile(keyRegex),
		cardPattern:             regexp.MustCompile(cardRegex),
		jwtPattern:              regexp.MustCompile(jwtRegex),
		bearerPattern:           regexp.MustCompile(bearerRegex),
		jsonKeyPattern:          regexp.MustCompile(jsonKeyRegex),
		formKeyPattern:          regexp.MustCompile(formKeyRegex),
	}
}

// Sanitize cleanses an in-flight ForensicEvent in-place.
func (s *Sanitizer) Sanitize(event *ForensicEvent) {
	if event == nil {
		return
	}

	// 1. Redact sensitive headers
	if event.Headers != nil {
		for key := range event.Headers {
			lower := strings.ToLower(key)
			if s.isSensitiveHeader(lower) {
				event.Headers[key] = RedactedValue
			}
		}
	}

	// 2. Scrub query parameters in URL Path
	if event.Path != "" {
		event.Path = s.SanitizePath(event.Path)
	}

	// 3. Scrub and truncate payload
	if event.TruncatedPayload != "" {
		// Cap initial regex scanning input to limit CPU time on massive payloads (e.g., 1MB bodies)
		if len(event.TruncatedPayload) > MaxPayloadBytes*2 {
			event.TruncatedPayload = truncateUTF8(event.TruncatedPayload, MaxPayloadBytes*2)
		}
		event.TruncatedPayload = s.SanitizePayload(event.TruncatedPayload)
		// Enforce hard context cap of 2 KB (2048 bytes) with valid UTF-8 boundary
		if len(event.TruncatedPayload) > MaxPayloadBytes {
			event.TruncatedPayload = truncateUTF8(event.TruncatedPayload, MaxPayloadBytes)
		}
	}
}

// Sanitize calls DefaultSanitizer.Sanitize.
func Sanitize(event *ForensicEvent) {
	DefaultSanitizer.Sanitize(event)
}

func (s *Sanitizer) isSensitiveHeader(lowerKey string) bool {
	if _, ok := s.sensitiveHeaderExact[lowerKey]; ok {
		return true
	}
	for _, prefix := range s.sensitiveHeaderPrefixes {
		if strings.HasPrefix(lowerKey, prefix) {
			return true
		}
	}
	return false
}

// SanitizePath scrubs sensitive query parameters and embedded tokens/PANs in a URL path.
func (s *Sanitizer) SanitizePath(rawPath string) string {
	qIdx := strings.IndexByte(rawPath, '?')
	if qIdx == -1 {
		return rawPath
	}

	base := rawPath[:qIdx]
	queryStr := rawPath[qIdx+1:]

	values, err := url.ParseQuery(queryStr)
	if err == nil && len(values) > 0 {
		for k := range values {
			lowerK := strings.ToLower(k)
			if s.isSensitiveKey(lowerK) {
				values[k] = []string{RedactedValue}
			} else {
				// Also check values for card numbers, JWTs, and bearer tokens
				for i, v := range values[k] {
					values[k][i] = s.scrubTokensAndCards(v)
				}
			}
		}
		encoded := values.Encode()
		encoded = strings.ReplaceAll(encoded, "%5BREDACTED%5D", RedactedValue)
		return base + "?" + encoded
	}

	// Fallback to regex scrubbing if url.ParseQuery encounters malformed queries
	queryStr = s.formKeyPattern.ReplaceAllString(queryStr, "${1}"+RedactedValue)
	queryStr = s.scrubTokensAndCards(queryStr)
	return base + "?" + queryStr
}

func (s *Sanitizer) isSensitiveKey(key string) bool {
	if s.sensitiveKeyPattern.MatchString(key) {
		return true
	}
	k := strings.ToLower(key)
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "cvv") ||
		strings.Contains(k, "api_key") ||
		strings.Contains(k, "card")
}

// SanitizePayload scrubs sensitive keys, credit cards, JWTs, and Bearer tokens from a payload string.
func (s *Sanitizer) SanitizePayload(payload string) string {
	// First scrub JSON keys
	payload = s.jsonKeyPattern.ReplaceAllString(payload, "${1}\""+RedactedValue+"\"")

	// Then scrub form/url encoded keys
	payload = s.formKeyPattern.ReplaceAllString(payload, "${1}"+RedactedValue)

	// Finally scrub any loose tokens and card numbers
	payload = s.scrubTokensAndCards(payload)

	return payload
}

func (s *Sanitizer) scrubTokensAndCards(text string) string {
	// Scrub Bearer tokens
	text = s.bearerPattern.ReplaceAllString(text, "Bearer "+RedactedValue)

	// Scrub JWTs
	text = s.jwtPattern.ReplaceAllString(text, RedactedValue)

	// Scrub Credit Card PANs (validate with Luhn)
	text = s.cardPattern.ReplaceAllStringFunc(text, func(match string) string {
		digits := extractDigits(match)
		if len(digits) >= 13 && len(digits) <= 19 && isValidLuhn(digits) {
			return RedactedValue
		}
		return match
	})

	return text
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isValidLuhn implements the standard Luhn checksum algorithm for PCI-DSS PAN validation.
func isValidLuhn(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

// truncateUTF8 safely truncates string s to at most maxBytes without cutting through multibyte UTF-8 runes.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
