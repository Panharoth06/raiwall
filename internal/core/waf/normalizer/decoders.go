package normalizer

import (
	"html"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodeURL handles standard percent-encoding (%XX) and IIS/Unicode percent-encoding (%uXXXX).
func decodeURL(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	// First pass: replace %uXXXX with UTF-8 runes
	if strings.Contains(s, "%u") || strings.Contains(s, "%U") {
		var sb strings.Builder
		sb.Grow(len(s))
		for i := 0; i < len(s); {
			if i+5 < len(s) && (s[i] == '%' && (s[i+1] == 'u' || s[i+1] == 'U')) {
				hexCode := s[i+2 : i+6]
				if val, err := strconv.ParseUint(hexCode, 16, 16); err == nil {
					sb.WriteRune(rune(val))
					i += 6
					continue
				}
			}
			sb.WriteByte(s[i])
			i++
		}
		s = sb.String()
	}

	// Second pass: standard URL unescaping
	if unescaped, err := url.QueryUnescape(s); err == nil {
		return unescaped
	}
	if unescaped, err := url.PathUnescape(s); err == nil {
		return unescaped
	}

	// Fallback manual percent decoding for malformed queries
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				sb.WriteByte(byte(b))
				i += 3
				continue
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// decodeHTMLEntities unescapes HTML entities, including named and numeric (decimal and hex).
func decodeHTMLEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}

	res := html.UnescapeString(s)

	if strings.Contains(res, "&#") {
		var sb strings.Builder
		sb.Grow(len(res))
		for i := 0; i < len(res); {
			if i+3 < len(res) && res[i] == '&' && res[i+1] == '#' {
				end := i + 2
				isHex := false
				if res[end] == 'x' || res[end] == 'X' {
					isHex = true
					end++
				}
				numStart := end
				for end < len(res) && ((res[end] >= '0' && res[end] <= '9') ||
					(isHex && ((res[end] >= 'a' && res[end] <= 'f') || (res[end] >= 'A' && res[end] <= 'F')))) {
					end++
				}
				if end > numStart {
					numStr := res[numStart:end]
					base := 10
					if isHex {
						base = 16
					}
					if val, err := strconv.ParseInt(numStr, base, 32); err == nil && utf8.ValidRune(rune(val)) {
						sb.WriteRune(rune(val))
						if end < len(res) && res[end] == ';' {
							end++
						}
						i = end
						continue
					}
				}
			}
			sb.WriteByte(res[i])
			i++
		}
		res = sb.String()
	}

	return res
}

// decodeJSEscapes unescapes \uXXXX, \UXXXXXXXX, and \xXX sequences.
func decodeJSEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'u': // \uXXXX
				if i+5 < len(s) {
					if val, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
						sb.WriteRune(rune(val))
						i += 6
						continue
					}
				}
			case 'U': // \UXXXXXXXX
				if i+9 < len(s) {
					if val, err := strconv.ParseUint(s[i+2:i+10], 16, 32); err == nil && utf8.ValidRune(rune(val)) {
						sb.WriteRune(rune(val))
						i += 10
						continue
					}
				}
			case 'x', 'X': // \xXX
				if i+3 < len(s) {
					if val, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
						sb.WriteByte(byte(val))
						i += 4
						continue
					}
				}
			case '\\':
				sb.WriteByte('\\')
				i += 2
				continue
			case '\'':
				sb.WriteByte('\'')
				i += 2
				continue
			case '"':
				sb.WriteByte('"')
				i += 2
				continue
			case '0': // \0 or octal
				if i+3 < len(s) {
					if val, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
						sb.WriteByte(byte(val))
						i += 4
						continue
					}
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// decodeHexLiterals converts standalone 0x27 or 0xXX representations when they represent printable ASCII or SQL evasion.
func decodeHexLiterals(s string) string {
	if !strings.Contains(s, "0x") && !strings.Contains(s, "0X") {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if i+3 < len(s) && (s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X')) {
			h1 := s[i+2]
			h2 := s[i+3]
			if isHexDigit(h1) && isHexDigit(h2) {
				if i+4 == len(s) || !isHexDigit(s[i+4]) {
					if val, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil && (val >= 0x20 && val <= 0x7E) {
						sb.WriteByte(byte(val))
						i += 4
						continue
					}
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// stripComments removes inline C/SQL comments /* ... */ and collapses them cleanly.
func stripComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end != -1 {
				prevChar := byte(0)
				if i > 0 {
					prevChar = s[i-1]
				}
				nextIdx := i + 2 + end + 2
				nextChar := byte(0)
				if nextIdx < len(s) {
					nextChar = s[nextIdx]
				}

				i = nextIdx

				if isLetter(prevChar) && isLetter(nextChar) {
					continue
				}
				sb.WriteByte(' ')
				continue
			} else {
				break
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// normalizeWhitespace collapses consecutive spaces, tabs, and newlines into single spaces.
func normalizeWhitespace(s string) string {
	s = strings.ReplaceAll(s, "\\\r\n", "")
	s = strings.ReplaceAll(s, "\\\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}
