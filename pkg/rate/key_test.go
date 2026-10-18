package rate

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestBuildCompositeKey(t *testing.T) {
	ip1 := net.ParseIP("203.0.113.10")
	ip2 := net.ParseIP("203.0.113.20")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"

	t.Run("Deterministic hash", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "rw_session", Value: "session-secret-abc"})

		key1 := BuildCompositeKey(ip1, ja4, req, "rw_session")
		key2 := BuildCompositeKey(ip1, ja4, req, "rw_session")

		if key1 != key2 {
			t.Errorf("expected deterministic keys, got %s and %s", key1, key2)
		}
		if len(key1) != 64 {
			t.Errorf("expected 64-char hex SHA-256 key, got length %d", len(key1))
		}
	})

	t.Run("Anti-CGNAT Isolation: Different cookies on same IP/JA4", func(t *testing.T) {
		reqUserA, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		reqUserA.AddCookie(&http.Cookie{Name: "session", Value: "user-alice-token"})

		reqUserB, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		reqUserB.AddCookie(&http.Cookie{Name: "session", Value: "user-bob-token"})

		keyA := BuildCompositeKey(ip1, ja4, reqUserA, "session")
		keyB := BuildCompositeKey(ip1, ja4, reqUserB, "session")

		if keyA == keyB {
			t.Fatalf("different users behind shared IP/JA4 must have distinct composite keys")
		}
	})

	t.Run("Cookie Privacy Protection", func(t *testing.T) {
		rawCookie := "super-secret-session-token-12345"
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "sid", Value: rawCookie})

		raw := BuildCompositeKeyRaw(ip1, ja4, req, "sid")
		if strings.Contains(raw, rawCookie) {
			t.Fatalf("raw composite key leaked sensitive cookie token: %s", raw)
		}
		expectedHash := HashString(rawCookie)
		if !strings.Contains(raw, expectedHash) {
			t.Errorf("raw composite key should contain hashed cookie %s, got %s", expectedHash, raw)
		}
	})

	t.Run("Automatic session cookie discovery", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "connect.sid", Value: "express-cookie-val"})

		// Leave cookieName empty to test auto-discovery
		raw := BuildCompositeKeyRaw(ip1, ja4, req, "")
		expectedHash := HashString("express-cookie-val")
		if !strings.Contains(raw, expectedHash) {
			t.Errorf("expected auto-discovered cookie hash in raw key, got: %s", raw)
		}
	})

	t.Run("Graceful degradation without cookie or JA4", func(t *testing.T) {
		// Only IP
		keyOnlyIP := BuildCompositeKey(ip1, "", nil, "")
		if keyOnlyIP == "" {
			t.Errorf("expected valid key with only IP")
		}

		// Different IPs produce different keys
		keyIP2 := BuildCompositeKey(ip2, "", nil, "")
		if keyOnlyIP == keyIP2 {
			t.Errorf("different IPs must produce different keys")
		}

		// Nil IP and empty JA4
		keyAnon := BuildCompositeKey(nil, "", nil, "")
		if keyAnon == "" {
			t.Errorf("expected valid key for anonymous request")
		}
	})
}
