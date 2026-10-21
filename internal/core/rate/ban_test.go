package rate

import (
	"context"
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

	t.Run("ListBans, Release, and ReleaseAll", func(t *testing.T) {
		bm.Ban(ip1, ja4_A, 30*time.Minute, "test_ban_1")
		bm.BanIP(ip2, 1*time.Hour, "test_ban_2")

		bans := bm.ListBans()
		if len(bans) != 2 {
			t.Fatalf("expected 2 active bans, got %d", len(bans))
		}

		foundIP2 := false
		for _, b := range bans {
			if b.ClientIP == ip2.String() {
				foundIP2 = true
				if b.RemainingSeconds <= 0 {
					t.Errorf("expected positive remaining seconds, got %d", b.RemainingSeconds)
				}
			}
		}
		if !foundIP2 {
			t.Errorf("expected to find ip2 in bans list")
		}

		// Release individual ban by IP
		released := bm.Release(ip2.String())
		if !released {
			t.Errorf("expected release of ip2 to succeed")
		}
		if len(bm.ListBans()) != 1 {
			t.Errorf("expected 1 active ban after releasing ip2")
		}

		// Unblock all emergency release
		var callbackCalled bool
		bm.SetOnUnblockAll(func() {
			callbackCalled = true
		})

		count := bm.ReleaseAll()
		if count != 1 {
			t.Errorf("expected 1 ban released, got %d", count)
		}
		if !callbackCalled {
			t.Errorf("expected unblock-all callback to be invoked")
		}
		if len(bm.ListBans()) != 0 {
			t.Errorf("expected 0 active bans after ReleaseAll")
		}
	})

	t.Run("BanStorage and OnUnblock integration", func(t *testing.T) {
		bm := NewBanManager(nil)
		defer bm.Close()

		mockStorage := &mockBanStorage{
			bans: make(map[string]*BanEntry),
		}
		bm.SetBanStorage(mockStorage)

		var unblocked string
		bm.SetOnUnblock(func(target string) {
			unblocked = target
		})

		entry := bm.BanWithSite(ip1, ja4_A, 1*time.Hour, "tier2_attack", "site-123")
		if entry.SiteID != "site-123" {
			t.Errorf("expected siteID site-123, got %s", entry.SiteID)
		}

		if len(mockStorage.bans) != 1 {
			t.Fatalf("expected ban stored in BanStorage")
		}

		// Verify ListBans includes external bans from storage
		externalIP := "198.51.100.222"
		mockStorage.bans[externalIP] = &BanEntry{
			Key:              externalIP,
			ClientIP:         externalIP,
			Reason:           "cluster_node_ban",
			Duration:         time.Hour,
			RemainingSeconds: 3600,
			BannedAt:         time.Now(),
			ExpiresAt:        time.Now().Add(time.Hour),
		}

		bans := bm.ListBans()
		if len(bans) != 2 {
			t.Errorf("expected 2 bans after merging with storage, got %d", len(bans))
		}

		// Release and verify OnUnblock and BanStorage.RemoveBan
		bm.Release(ip1.String())
		if unblocked != ip1.String() {
			t.Errorf("expected OnUnblock callback with %s, got %s", ip1.String(), unblocked)
		}
		if _, exists := mockStorage.bans[ip1.String()]; exists {
			t.Errorf("expected ban removed from BanStorage")
		}

		// ReleaseAll and verify BanStorage.ClearBans
		bm.ReleaseAll()
		if len(mockStorage.bans) != 0 {
			t.Errorf("expected BanStorage cleared on ReleaseAll")
		}
	})
}

type mockBanStorage struct {
	bans map[string]*BanEntry
}

func (m *mockBanStorage) StoreBan(ctx context.Context, entry *BanEntry) error {
	m.bans[entry.Key] = entry
	return nil
}

func (m *mockBanStorage) RemoveBan(ctx context.Context, keyOrIP string) error {
	delete(m.bans, keyOrIP)
	for k, e := range m.bans {
		if e.ClientIP == keyOrIP || e.Key == keyOrIP {
			delete(m.bans, k)
		}
	}
	return nil
}

func (m *mockBanStorage) ClearBans(ctx context.Context) error {
	m.bans = make(map[string]*BanEntry)
	return nil
}

func (m *mockBanStorage) ListBans(ctx context.Context) ([]*BanEntry, error) {
	res := make([]*BanEntry, 0, len(m.bans))
	for _, b := range m.bans {
		res = append(res, b)
	}
	return res, nil
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
