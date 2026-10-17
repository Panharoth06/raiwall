package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/raiwall/raiwall/pkg/config"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestUpstreamPoolLoadBalancingAndHealthChecks(t *testing.T) {
	var b2Healthy atomic.Bool
	b2Healthy.Store(true)

	addr1 := "backend1.internal:8080"
	addr2 := "backend2.internal:8080"

	targets := []config.UpstreamTarget{
		{
			Dial:                addr1,
			Weight:              1,
			MaxFails:            2,
			HealthCheckPath:     "/healthz",
			HealthCheckInterval: 20 * time.Millisecond,
		},
		{
			Dial:                addr2,
			Weight:              1,
			MaxFails:            2,
			HealthCheckPath:     "/healthz",
			HealthCheckInterval: 20 * time.Millisecond,
		},
	}

	pool := NewUpstreamPool(targets)
	backends := pool.Backends()

	// Backend 1 transport: always 200 OK
	backends[0].Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	})

	// Backend 2 transport: conditionally 200 or 500
	backends[1].Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusOK
		if !b2Healthy.Load() {
			status = http.StatusInternalServerError
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("status")),
			Header:     make(http.Header),
		}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pool.Stop()

	pool.StartHealthChecks(ctx)

	// Wait briefly for first health check
	time.Sleep(50 * time.Millisecond)

	// 1. Verify both backends healthy and traffic alternates (Round-Robin)
	healthy := pool.HealthyBackends()
	if len(healthy) != 2 {
		t.Fatalf("expected 2 healthy backends, got %d", len(healthy))
	}

	for i := 0; i < 10; i++ {
		backend, err := pool.NextBackend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend.Dial != addr1 && backend.Dial != addr2 {
			t.Errorf("unexpected backend dial: %s", backend.Dial)
		}
	}

	// 2. Mark backend 2 as failing
	b2Healthy.Store(false)

	// Wait for MaxFails (2) intervals (20ms * 3 = 60ms)
	time.Sleep(80 * time.Millisecond)

	// Backend 2 should now be evicted
	healthyAfterFail := pool.HealthyBackends()
	if len(healthyAfterFail) != 1 {
		t.Fatalf("expected 1 healthy backend after failure, got %d", len(healthyAfterFail))
	}
	if healthyAfterFail[0].Dial != addr1 {
		t.Errorf("expected remaining healthy backend to be %s, got %s", addr1, healthyAfterFail[0].Dial)
	}

	// All NextBackend calls should now route exclusively to backend 1
	for i := 0; i < 5; i++ {
		b, err := pool.NextBackend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Dial != addr1 {
			t.Errorf("expected backend 1, got %s", b.Dial)
		}
	}

	// 3. Recover backend 2
	b2Healthy.Store(true)
	time.Sleep(60 * time.Millisecond)

	healthyRecovered := pool.HealthyBackends()
	if len(healthyRecovered) != 2 {
		t.Fatalf("expected 2 healthy backends after recovery, got %d", len(healthyRecovered))
	}
}

func TestUpstreamPoolAllUnhealthy(t *testing.T) {
	targets := []config.UpstreamTarget{
		{Dial: "127.0.0.1:59999", MaxFails: 1, HealthCheckPath: "/healthz"},
	}
	pool := NewUpstreamPool(targets)
	defer pool.Stop()

	// Simulate failure
	backend, err := pool.NextBackend()
	if err != nil {
		t.Fatalf("expected initial backend, got err: %v", err)
	}
	backend.recordFailure()

	_, err = pool.NextBackend()
	if err == nil {
		t.Fatal("expected error when all backends unhealthy, got nil")
	}
}

func TestUpstreamPoolWeightedRoundRobin(t *testing.T) {
	targets := []config.UpstreamTarget{
		{Dial: "backend-a:8080", Weight: 3},
		{Dial: "backend-b:8080", Weight: 1},
	}
	pool := NewUpstreamPool(targets)
	defer pool.Stop()

	counts := make(map[string]int)
	const totalRequests = 40
	for i := 0; i < totalRequests; i++ {
		b, err := pool.NextBackend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		counts[b.Dial]++
	}

	if counts["backend-a:8080"] != 30 {
		t.Errorf("backend-a count = %d, want 30", counts["backend-a:8080"])
	}
	if counts["backend-b:8080"] != 10 {
		t.Errorf("backend-b count = %d, want 10", counts["backend-b:8080"])
	}
}
