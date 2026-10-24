package auth

import (
	"net/url"
	"strings"
)

// isSafeRedirect validates that a redirect target is a safe local relative URL.
// Prevents Open Redirect and XSS via javascript:/data: pseudo-protocols or
// protocol-relative //evil.com / \evil.com bypasses.
func isSafeRedirect(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	if !strings.HasPrefix(urlStr, "/") || strings.HasPrefix(urlStr, "//") || strings.HasPrefix(urlStr, "/\\") || strings.HasPrefix(urlStr, "\\") {
		return false
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return false
	}
	for _, b := range []byte(urlStr) {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}
