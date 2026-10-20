package rate

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTier2AttackLimiter(t *testing.T) {
	banMgr := NewBanManager(nil)
	defer banMgr.Close()

	cfg := Tier2Config{
		Threshold:          3, // 3 attacks trigger auto-ban
		Window:             time.Second,
		BanDuration:        1 * time.Hour,
		BanManager:         banMgr,
		EnableIPEscalation: true,
		IPThreshold:        5, // 5 attacks from same IP across JA4s trigger IP ban
	}

	t2 := NewTier2AttackLimiter(cfg)
	defer t2.Close()

	ctx := context.Background()
	ip := net.ParseIP("198.51.100.55")
	ja4_1 := "t13d1516h2_8daaf6152771_0123456789ab"
	ja4_2 := "t12d0804h1_123456789012_abcdefabcdef"

	t.Run("Attacks below threshold do not trigger ban", func(t *testing.T) {
		banned, entry, err := t2.RecordAttack(ctx, ip, ja4_1, "SEMANTIC_SQLI", "1' OR '1'='1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if banned || entry != nil {
			t.Fatalf("attack 1 should not trigger ban")
		}

		banned, entry, err = t2.RecordAttack(ctx, ip, ja4_1, "SEMANTIC_XSS", "<script>alert(1)</script>")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if banned || entry != nil {
			t.Fatalf("attack 2 should not trigger ban")
		}

		// Verify not in BanManager
		isBanned, _ := banMgr.IsBanned(ip, ja4_1)
		if isBanned {
			t.Fatalf("client should not be banned yet")
		}
	})

	t.Run("Threshold breach triggers immediate auto-ban", func(t *testing.T) {
		// Attacks 3 and 4 (since capacity was threshold 3):
		// 3rd attack is conforming or 4th breaches
		_, _, _ = t2.RecordAttack(ctx, ip, ja4_1, "SEMANTIC_CMDI", "; cat /etc/passwd")
		banned, entry, err := t2.RecordAttack(ctx, ip, ja4_1, "SEMANTIC_CMDI", "; id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !banned || entry == nil {
			t.Fatalf("exceeding attack threshold should trigger auto-ban")
		}

		// Fast-path lookup in BanManager must immediately show banned
		isBanned, activeEntry := banMgr.IsBanned(ip, ja4_1)
		if !isBanned || activeEntry == nil {
			t.Fatalf("BanManager should immediately reflect auto-ban")
		}

		// Different JA4 on same IP is NOT banned (anti-CGNAT!)
		isBanned2, _ := banMgr.IsBanned(ip, ja4_2)
		if isBanned2 {
			t.Fatalf("ja4_2 on same IP should remain unbanned (anti-CGNAT protection)")
		}
	})

	t.Run("Pure IP escalation when multiple JA4s attack", func(t *testing.T) {
		escIP := net.ParseIP("198.51.100.88")
		// Send attacks with rotating JA4 fingerprints to evade single-client threshold
		for i := 0; i < 7; i++ {
			rotJA4 := "ja4-rotation-" + string(rune('A'+i))
			banned, entry, _ := t2.RecordAttack(ctx, escIP, rotJA4, "SEMANTIC_SQLI", "union select")
			if banned && entry != nil && entry.JA4 == "" {
				// Pure IP escalation ban triggered!
				isBanned, _ := banMgr.IsBanned(escIP, "any-ja4-should-be-banned")
				if !isBanned {
					t.Fatalf("expected pure IP ban to block all JA4s from %s", escIP)
				}
				return
			}
		}
		// Check if IP is banned
		isBanned, _ := banMgr.IsBanned(escIP, "unseen-ja4")
		if !isBanned {
			t.Fatalf("expected pure IP escalation ban for %s", escIP)
		}
	})
}
