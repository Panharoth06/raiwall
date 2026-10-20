package rate

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMemoryStorage_Eviction(t *testing.T) {
	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()
	cfg := RateLimitConfig{
		Rate:   10,
		Period: 100 * time.Millisecond,
		Burst:  1,
	}

	// Add entries
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("evict-key-%d", i)
		_, err := storage.EvalGCRA(ctx, key, cfg, 1, time.Now())
		if err != nil {
			t.Fatalf("EvalGCRA failed: %v", err)
		}
	}

	if storage.Count() != 10 {
		t.Fatalf("expected 10 keys, got %d", storage.Count())
	}

	// Manually advance time by evaluating expiration
	// In memory.go, expiration is newTAT + tau + T + 1s.
	// Force eviction by simulating expiration
	for _, shard := range storage.shards {
		shard.mu.Lock()
		for k := range shard.exp {
			shard.exp[k] = time.Now().Add(-1 * time.Hour).UnixNano()
		}
		shard.mu.Unlock()
	}

	evicted := storage.EvictExpired()
	if evicted != 10 {
		t.Errorf("expected 10 evicted keys, got %d", evicted)
	}
	if storage.Count() != 0 {
		t.Errorf("expected 0 keys remaining, got %d", storage.Count())
	}
}

func BenchmarkGCRAInMem(b *testing.B) {
	cfg := RateLimitConfig{
		Rate:   1000000,
		Period: time.Second,
		Burst:  100000,
	}

	storage := NewMemoryStorage()
	defer storage.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-ip-%d", i%1000)
			_, _ = storage.EvalGCRA(ctx, key, cfg, 1, time.Now())
			i++
		}
	})
}
