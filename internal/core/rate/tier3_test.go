package rate

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTier3ScannerTrap(t *testing.T) {
	banMgr := NewBanManager(nil)
	defer banMgr.Close()

	cfg := Tier3Config{
		Threshold:   3, // 3 404s/403s trigger auto-ban
		Window:      time.Second,
		BanDuration: 1 * time.Hour,
		BanManager:  banMgr,
		CookieName:  "session",
	}

	t3 := NewTier3ScannerTrap(cfg)
	defer t3.Close()

	ctx := context.Background()
	ip := net.ParseIP("198.51.100.99")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"
	ja4_innocent := "t12d0804h1_123456789012_abcdefabcdef"

	t.Run("Static assets bypass scanner trap", func(t *testing.T) {
		staticPaths := []string{
			"/images/logo.png",
			"/css/style.css",
			"/fonts/inter.woff2",
			"/favicon.ico",
			"/bundle.js",
			"/app.js.map",
		}

		for _, p := range staticPaths {
			req := httptest.NewRequest(http.MethodGet, "https://example.com"+p, nil)
			banned, entry, err := t3.InspectResponse(ctx, req, ip, ja4, http.StatusNotFound)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if banned || entry != nil {
				t.Fatalf("static asset %s 404 should be bypassed", p)
			}
		}

		// Ensure client was not banned
		isBanned, _ := banMgr.IsBanned(ip, ja4)
		if isBanned {
			t.Fatalf("client should not be banned for missing static assets")
		}
	})

	t.Run("Non-error status codes are ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
		for _, code := range []int{http.StatusOK, http.StatusMovedPermanently, http.StatusInternalServerError} {
			banned, entry, err := t3.InspectResponse(ctx, req, ip, ja4, code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if banned || entry != nil {
				t.Fatalf("status %d should be ignored by scanner trap", code)
			}
		}
	})

	t.Run("Directory bruteforcing triggers auto-ban", func(t *testing.T) {
		fuzzPaths := []string{
			"/.env",
			"/admin/config.php",
			"/wp-login.php",
			"/backup.zip",
		}

		scannerReq := httptest.NewRequest(http.MethodGet, "https://example.com"+fuzzPaths[0], nil)

		// 1st and 2nd 404s
		banned, _, _ := t3.InspectResponse(ctx, scannerReq, ip, ja4, http.StatusNotFound)
		if banned {
			t.Fatalf("1st 404 should not ban")
		}

		scannerReq2 := httptest.NewRequest(http.MethodGet, "https://example.com"+fuzzPaths[1], nil)
		banned, _, _ = t3.InspectResponse(ctx, scannerReq2, ip, ja4, http.StatusForbidden)
		if banned {
			t.Fatalf("2nd 403 should not ban")
		}

		// 3rd and 4th: breaches threshold
		scannerReq3 := httptest.NewRequest(http.MethodGet, "https://example.com"+fuzzPaths[2], nil)
		_, _, _ = t3.InspectResponse(ctx, scannerReq3, ip, ja4, http.StatusNotFound)

		scannerReq4 := httptest.NewRequest(http.MethodGet, "https://example.com"+fuzzPaths[3], nil)
		banned, entry, err := t3.InspectResponse(ctx, scannerReq4, ip, ja4, http.StatusNotFound)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !banned || entry == nil {
			t.Fatalf("expected scanner to be auto-banned after exceeding 404 threshold")
		}

		// Verify scanner is recorded in BanManager
		isBanned, _ := banMgr.IsBanned(ip, ja4)
		if !isBanned {
			t.Fatalf("scanner should be registered in BanManager")
		}

		// Anti-CGNAT: Innocent user on same IP with different JA4 is NOT banned!
		isInnocentBanned, _ := banMgr.IsBanned(ip, ja4_innocent)
		if isInnocentBanned {
			t.Fatalf("innocent user on shared IP should NOT be banned (anti-CGNAT protection)")
		}
	})
}
