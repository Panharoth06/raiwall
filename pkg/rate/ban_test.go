package rate

import (
	"net"
	"testing"
	"time"
)

func TestBanManager(t *testing.T) {
	bm := NewBanManager(nil)
	defer bm.Close()

	ip1 := net.ParseIP("198.51.100.10")
	ip2 := net.ParseIP("198.51.100.20")
	ja4_A := "t13d1516h2_8daaf6152771_0123456789ab"
	ja4_B := "t12d0804h1_123456789012_abcdefabcdef"

	t.Run("Composite ban protects innocent users on same IP", func(t *testing.T) {
		// Ban specific client (ip1 + ja4_A)
		bm.Ban(ip1, ja4_A, 1*time.Hour, "crawler_botnet")

		// Attacker is banned
		banned, entry := bm.IsBanned(ip1, ja4_A)
		if !banned || entry == nil {
			t.Fatalf("expected attacker (ip1 + ja4_A) to be banned")
		}
		if entry.Reason != "crawler_botnet" {
			t.Errorf("unexpected ban reason: %s", entry.Reason)
		}

		// Innocent user on same IP with different JA4 is NOT banned!
		bannedB, _ := bm.IsBanned(ip1, ja4_B)
		if bannedB {
			t.Fatalf("innocent user (ip1 + ja4_B) on same IP should NOT be banned (anti-CGNAT protection)")
		}

		// Different IP with same JA4 is NOT banned
		bannedIP2, _ := bm.IsBanned(ip2, ja4_A)
		if bannedIP2 {
			t.Fatalf("user on ip2 should not be affected by ban on ip1")
		}
	})

	t.Run("Pure IP ban blocks all traffic from that IP", func(t *testing.T) {
		bm.BanIP(ip2, 2*time.Hour, "ddos_origin")

		// Any JA4 from ip2 is banned
		bannedA, _ := bm.IsBanned(ip2, ja4_A)
		if !bannedA {
			t.Errorf("expected ip2 to be banned for ja4_A")
		}

		bannedB, _ := bm.IsBanned(ip2, ja4_B)
		if !bannedB {
			t.Errorf("expected ip2 to be banned for ja4_B")
		}

		// Unban IP
		bm.UnbanIP(ip2)
		bannedAfter, _ := bm.IsBanned(ip2, ja4_A)
		if bannedAfter {
			t.Errorf("ip2 should be unbanned")
		}
	})

	t.Run("TTL expiration", func(t *testing.T) {
		shortIP := net.ParseIP("198.51.100.99")
		bm.Ban(shortIP, ja4_A, 10*time.Millisecond, "short_ban")

		banned, _ := bm.IsBanned(shortIP, ja4_A)
		if !banned {
			t.Fatalf("should be banned initially")
		}

		time.Sleep(20 * time.Millisecond)

		bannedExpired, _ := bm.IsBanned(shortIP, ja4_A)
		if bannedExpired {
			t.Fatalf("should no longer be banned after TTL expires")
		}

		evicted := bm.EvictExpired()
		if evicted == 0 {
			t.Errorf("expected at least 1 key evicted")
		}
	})
}

func BenchmarkBanLookup(b *testing.B) {
	bm := NewBanManager(nil)
	defer bm.Close()

	ip := net.ParseIP("198.51.100.1")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"
	bm.Ban(ip, ja4, 1*time.Hour, "benchmark_ban")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = bm.IsBanned(ip, ja4)
		}
	})
}
