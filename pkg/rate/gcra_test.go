package rate

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestGCRAMath(t *testing.T) {
	t.Run("Steady rate and burst limits", func(t *testing.T) {
		cfg := RateLimitConfig{
			Rate:   5,
			Period: time.Second, // T = 200ms
			Burst:  2,           // tau = 400ms, capacity = 1 + 2 = 3
		}

		now := time.Now()
		var tat int64

		// 1st request at t = 0 -> allowed
		newTAT, res := CalculateGCRA(now, tat, false, cfg, 1)
		if !res.Allowed {
			t.Fatalf("1st request should be allowed")
		}
		if res.Remaining != 2 {
			t.Errorf("expected 2 remaining, got %d", res.Remaining)
		}
		tat = newTAT

		// 2nd request at t = 0 -> allowed
		newTAT, res = CalculateGCRA(now, tat, true, cfg, 1)
		if !res.Allowed {
			t.Fatalf("2nd request should be allowed")
		}
		if res.Remaining != 1 {
			t.Errorf("expected 1 remaining, got %d", res.Remaining)
		}
		tat = newTAT

		// 3rd request at t = 0 -> allowed
		newTAT, res = CalculateGCRA(now, tat, true, cfg, 1)
		if !res.Allowed {
			t.Fatalf("3rd request should be allowed")
		}
		if res.Remaining != 0 {
			t.Errorf("expected 0 remaining, got %d", res.Remaining)
		}
		tat = newTAT

		// 4th request at t = 0 -> rejected
		_, res = CalculateGCRA(now, tat, true, cfg, 1)
		if res.Allowed {
			t.Fatalf("4th request at t=0 should be rejected")
		}
		if res.RetryAfter < 190*time.Millisecond || res.RetryAfter > 210*time.Millisecond {
			t.Errorf("expected RetryAfter ~200ms, got %v", res.RetryAfter)
		}

		// 5th request at t = 200ms -> allowed again
		now2 := now.Add(200 * time.Millisecond)
		newTAT, res = CalculateGCRA(now2, tat, true, cfg, 1)
		if !res.Allowed {
			t.Fatalf("request at t=200ms should be allowed, got retryAfter=%v", res.RetryAfter)
		}
		if res.Remaining != 0 {
			t.Errorf("expected 0 remaining, got %d", res.Remaining)
		}
	})

	t.Run("Cost exceeding capacity", func(t *testing.T) {
		cfg := RateLimitConfig{
			Rate:   10,
			Period: time.Second, // T = 100ms
			Burst:  1,           // capacity = 2 requests
		}
		now := time.Now()

		// Request with cost 5 (> capacity of 2)
		_, res := CalculateGCRA(now, 0, false, cfg, 5)
		if res.Allowed {
			t.Errorf("cost exceeding total burst capacity should be rejected")
		}
	})

	t.Run("Defaults for empty or zero config", func(t *testing.T) {
		cfg := RateLimitConfig{}
		now := time.Now()
		_, res := CalculateGCRA(now, 0, false, cfg, 0)
		if !res.Allowed {
			t.Errorf("should allow with defaulted config")
		}
		if res.Limit != 1 {
			t.Errorf("expected default limit 1, got %d", res.Limit)
		}
	})
}

func TestGCRALimiter(t *testing.T) {
	cfg := RateLimitConfig{
		Rate:   10,
		Period: time.Second,
		Burst:  5,
	}

	storage := NewMemoryStorage()
	defer storage.Close()
	limiter := NewGCRALimiter(storage, cfg)
	defer limiter.Close()

	ctx := context.Background()
	key := "client-127.0.0.1"

	// Should allow first 6 requests (1 + burst 5)
	for i := 0; i < 6; i++ {
		res, err := limiter.Allow(ctx, key, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 7th should be rejected
	res, err := limiter.Allow(ctx, key, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatalf("7th request should be rejected")
	}
	if res.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %v", res.RetryAfter)
	}

	// Reset key
	if err := limiter.Reset(ctx, key); err != nil {
		t.Fatalf("failed to reset key: %v", err)
	}

	// Should be allowed again immediately
	res, err = limiter.Allow(ctx, key, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("request after reset should be allowed")
	}
}

func TestGCRALimiterConcurrent(t *testing.T) {
	cfg := RateLimitConfig{
		Rate:   1000,
		Period: time.Second,
		Burst:  100,
	}

	limiter := NewMemoryLimiter(cfg)
	defer limiter.Close()

	ctx := context.Background()
	const numGoroutines = 50
	const requestsPerGoroutine = 20

	var wg sync.WaitGroup
	var allowedCount int64
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				key := "shared-client"
				res, err := limiter.Allow(ctx, key, 1)
				if err == nil && res.Allowed {
					mu.Lock()
					allowedCount++
					mu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	// Initial burst capacity is 1 + 100 = 101
	if allowedCount > 150 {
		t.Errorf("allowed too many requests under immediate burst: %d", allowedCount)
	}
	if allowedCount == 0 {
		t.Errorf("expected some allowed requests, got 0")
	}
}
