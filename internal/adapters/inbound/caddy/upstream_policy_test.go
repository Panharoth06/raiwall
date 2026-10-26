package caddy

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

func lbTestPool() *UpstreamPool {
	return NewUpstreamPool([]control.UpstreamTarget{
		{Dial: "10.0.0.1:80", Weight: 1},
		{Dial: "10.0.0.2:80", Weight: 1},
	})
}

func TestSelectBackendRoundRobin(t *testing.T) {
	pool := lbTestPool()
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		backend, release, err := pool.SelectBackend(control.LoadBalanceRoundRobin, "203.0.113.7")
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		release()
		seen[backend.Dial]++
	}
	if seen["10.0.0.1:80"] != 3 || seen["10.0.0.2:80"] != 3 {
		t.Fatalf("round robin did not distribute evenly: %+v", seen)
	}
}

func TestSelectBackendIPHashIsSticky(t *testing.T) {
	pool := lbTestPool()
	first, _, err := pool.SelectBackend(control.LoadBalanceIPHash, "198.51.100.10")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	for i := 0; i < 8; i++ {
		got, _, err := pool.SelectBackend(control.LoadBalanceIPHash, "198.51.100.10")
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if got.Dial != first.Dial {
			t.Fatalf("ip_hash switched backend: %s != %s", got.Dial, first.Dial)
		}
	}
}

func TestSelectBackendLeastConnections(t *testing.T) {
	pool := lbTestPool()
	first, releaseFirst, err := pool.SelectBackend(control.LoadBalanceLeastConn, "")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	// While the first backend holds a connection, the second is least loaded.
	second, releaseSecond, err := pool.SelectBackend(control.LoadBalanceLeastConn, "")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if first.Dial == second.Dial {
		t.Fatalf("least_conn reused the busiest backend: %s", first.Dial)
	}
	releaseSecond()

	third, releaseThird, err := pool.SelectBackend(control.LoadBalanceLeastConn, "")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	releaseThird()
	if third.Dial != second.Dial {
		t.Fatalf("least_conn did not pick the idle backend: got %s want %s", third.Dial, second.Dial)
	}
	releaseFirst()
}

func TestSelectBackendPrimaryBackup(t *testing.T) {
	pool := lbTestPool()
	for i := 0; i < 5; i++ {
		backend, _, err := pool.SelectBackend(control.LoadBalancePrimaryBackup, "")
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if backend.Dial != "10.0.0.1:80" {
			t.Fatalf("primary_backup served %s, want primary", backend.Dial)
		}
	}
}

func TestSelectBackendSkipsUnhealthy(t *testing.T) {
	pool := lbTestPool()
	backends := pool.Backends()
	backends[0].healthy.Store(false)

	for i := 0; i < 4; i++ {
		backend, _, err := pool.SelectBackend(control.LoadBalanceRoundRobin, "")
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if backend.Dial != "10.0.0.2:80" {
			t.Fatalf("served unhealthy backend %s", backend.Dial)
		}
	}

	backends[1].healthy.Store(false)
	if _, _, err := pool.SelectBackend(control.LoadBalanceRoundRobin, ""); err == nil {
		t.Fatal("expected error when every backend is unhealthy")
	}
	if _, release, err := pool.SelectBackend(control.LoadBalanceLeastConn, ""); err == nil {
		release()
		t.Fatal("expected error when every backend is unhealthy")
	}
}

func TestSelectBackendEmptyPool(t *testing.T) {
	pool := NewUpstreamPool(nil)
	if _, _, err := pool.SelectBackend(control.LoadBalanceRoundRobin, ""); err == nil {
		t.Fatal("expected error for empty pool")
	}
}
