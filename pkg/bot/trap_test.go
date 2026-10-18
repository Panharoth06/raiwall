package bot

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrapController_AutoBan(t *testing.T) {
	banDuration := 100 * time.Millisecond
	controller := NewTrapController(nil, banDuration, nil)

	ip := net.ParseIP("198.51.100.25")
	ja4 := "t13d1516h2_crawler_hash"

	// Initially not banned
	banned, _ := controller.IsClientBanned(ip, ja4)
	if banned {
		t.Fatalf("Client should not be banned initially")
	}

	// Trip the trap
	req := httptest.NewRequest(http.MethodGet, "/.raiwall/trap/crawler", nil)
	rec := httptest.NewRecorder()

	controller.HandleTrap(rec, req, ip, ja4)

	res := rec.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("HandleTrap StatusCode = %d, want 403", res.StatusCode)
	}

	// Now client must be banned
	banned, entry := controller.IsClientBanned(ip, ja4)
	if !banned || entry == nil {
		t.Fatalf("Expected client to be banned immediately after trap trip")
	}
	if entry.JA4 != ja4 || entry.ClientIP != ip.String() {
		t.Errorf("BanEntry mismatch: %+v", entry)
	}

	// Wait for TTL expiration
	time.Sleep(150 * time.Millisecond)

	bannedExpired, _ := controller.IsClientBanned(ip, ja4)
	if bannedExpired {
		t.Errorf("Client should no longer be banned after TTL expiration")
	}
}

func TestMemoryBanStore_Operations(t *testing.T) {
	store := NewMemoryBanStore()
	defer store.Close()

	ip1 := net.ParseIP("10.0.0.1")
	ja4_1 := "ja4_hash_1"

	ip2 := net.ParseIP("10.0.0.2")
	ja4_2 := "ja4_hash_2"

	store.Ban(ip1, ja4_1, 1*time.Hour, "test ban 1")
	store.Ban(ip2, ja4_2, 1*time.Hour, "test ban 2")

	if store.Count() != 2 {
		t.Errorf("Count() = %d, want 2", store.Count())
	}

	banned, _ := store.IsBanned(ip1, ja4_1)
	if !banned {
		t.Errorf("ip1 should be banned")
	}

	key1 := ClientBanKey(ip1, ja4_1)
	store.Unban(key1)

	bannedAfterUnban, _ := store.IsBanned(ip1, ja4_1)
	if bannedAfterUnban {
		t.Errorf("ip1 should be unbanned")
	}

	if store.Count() != 1 {
		t.Errorf("Count() = %d, want 1 after unban", store.Count())
	}

	store.Clear()
	if store.Count() != 0 {
		t.Errorf("Count() = %d, want 0 after Clear", store.Count())
	}
}

func TestMemoryBanStore_EvictExpired(t *testing.T) {
	store := NewMemoryBanStore()
	defer store.Close()

	ip := net.ParseIP("192.0.2.10")
	store.Ban(ip, "ja4_short_ttl", 50*time.Millisecond, "short ttl ban")

	if store.Count() != 1 {
		t.Fatalf("expected count 1, got %d", store.Count())
	}

	time.Sleep(100 * time.Millisecond)

	evicted := store.EvictExpired()
	if evicted != 1 {
		t.Errorf("EvictExpired() = %d, want 1", evicted)
	}

	if store.Count() != 0 {
		t.Errorf("Count() = %d after eviction, want 0", store.Count())
	}
}
