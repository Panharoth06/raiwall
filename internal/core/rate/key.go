package rate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// CommonSessionCookies lists typical cookie names used for session tracking.
var CommonSessionCookies = []string{
	"rw_session",
	"session",
	"session_id",
	"sessionid",
	"sid",
	"connect.sid",
	"PHPSESSID",
	"JSESSIONID",
	"aspsessionid",
}

// HashString returns the SHA-256 hexadecimal string of s.
func HashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// BuildCompositeKeyRaw returns the human-readable composite tuple:
// "ip:<ip>|ja4:<ja4>|c:<cookie_hash>"
// If cookie is present, its value is hashed with SHA-256 to protect user privacy.
func BuildCompositeKeyRaw(ip net.IP, ja4 string, r *http.Request, cookieName string) string {
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	cookieHash := ""
	if r != nil {
		if cookieName != "" {
			if c, err := r.Cookie(cookieName); err == nil && strings.TrimSpace(c.Value) != "" {
				cookieHash = HashString(strings.TrimSpace(c.Value))
			}
		} else {
			for _, name := range CommonSessionCookies {
				if c, err := r.Cookie(name); err == nil && strings.TrimSpace(c.Value) != "" {
					cookieHash = HashString(strings.TrimSpace(c.Value))
					break
				}
			}
		}
	}

	return fmt.Sprintf("ip:%s|ja4:%s|c:%s", ipStr, ja4, cookieHash)
}

// BuildCompositeKey constructs a unique, anti-CGNAT tracking key incorporating
// ClientIP, JA4 fingerprint, and Session Cookie.
// It returns a deterministic 64-character SHA-256 hexadecimal digest.
func BuildCompositeKey(ip net.IP, ja4 string, r *http.Request, cookieName string) string {
	raw := BuildCompositeKeyRaw(ip, ja4, r, cookieName)
	return HashString(raw)
}
