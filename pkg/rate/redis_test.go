package rate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockRedisClient struct {
	evalFunc func(ctx context.Context, script string, keys []string, args ...any) (any, error)
	delFunc  func(ctx context.Context, keys ...string) error
	pingFunc func(ctx context.Context) error
}

func (m *mockRedisClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	if m.evalFunc != nil {
		return m.evalFunc(ctx, script, keys, args...)
	}
	return []any{int64(1), int64(9), int64(0), int64(100)}, nil
}

func (m *mockRedisClient) Del(ctx context.Context, keys ...string) error {
	if m.delFunc != nil {
		return m.delFunc(ctx, keys...)
	}
	return nil
}

func (m *mockRedisClient) Ping(ctx context.Context) error {
	if m.pingFunc != nil {
		return m.pingFunc(ctx)
	}
	return nil
}

func (m *mockRedisClient) Close() error {
	return nil
}

func TestRedisStorage_EvalAndParsing(t *testing.T) {
	mockClient := &mockRedisClient{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			// Returns {allowed, remaining, retry_after_ms, reset_after_ms}
			return []any{int64(1), int64(4), int64(0), int64(250)}, nil
		},
	}

	storage := NewRedisStorage(RedisStorageConfig{
		Client:            mockClient,
		KeyPrefix:         "test:rate:",
		FallbackOnFailure: true,
	})
	defer storage.Close()

	cfg := RateLimitConfig{Rate: 10, Period: time.Second, Burst: 5}
	res, err := storage.EvalGCRA(context.Background(), "user1", cfg, 1, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Errorf("expected allowed=true")
	}
	if res.Remaining != 4 {
		t.Errorf("expected remaining=4, got %d", res.Remaining)
	}
	if res.ResetAfter != 250*time.Millisecond {
		t.Errorf("expected resetAfter=250ms, got %v", res.ResetAfter)
	}
}

func TestRedisStorage_FallbackToMemoryOnFailure(t *testing.T) {
	mockClient := &mockRedisClient{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			return nil, errors.New("connection refused: redis cluster unavailable")
		},
	}

	storage := NewRedisStorage(RedisStorageConfig{
		Client:            mockClient,
		FallbackOnFailure: true,
	})
	defer storage.Close()

	cfg := RateLimitConfig{Rate: 2, Period: time.Second, Burst: 0}
	ctx := context.Background()

	// 1st request should succeed via fallback memory storage
	res1, err := storage.EvalGCRA(ctx, "fallback-key", cfg, 1, time.Now())
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if !res1.Allowed {
		t.Fatalf("1st request should be allowed in fallback")
	}

	// 2nd request at t=0 should be rejected by memory storage (burst=0)
	res2, err := storage.EvalGCRA(ctx, "fallback-key", cfg, 1, time.Now())
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if res2.Allowed {
		t.Fatalf("2nd request should be rate limited by fallback")
	}
}

func TestRedisStorage_ConnectionRecovery(t *testing.T) {
	storage := NewRedisStorage(RedisStorageConfig{
		Client:            nil, // Initially disconnected
		FallbackOnFailure: true,
	})
	defer storage.Close()

	cfg := RateLimitConfig{Rate: 10, Period: time.Second, Burst: 2}
	ctx := context.Background()

	// Evaluates on fallback
	res, err := storage.EvalGCRA(ctx, "recover-key", cfg, 1, time.Now())
	if err != nil || !res.Allowed {
		t.Fatalf("fallback failed: %v", err)
	}

	// Restore connection
	recoveredClient := &mockRedisClient{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			return []any{int64(1), int64(7), int64(0), int64(500)}, nil
		},
	}
	storage.SetClient(recoveredClient)

	// Now evaluates on restored Redis client
	res2, err := storage.EvalGCRA(ctx, "recover-key", cfg, 1, time.Now())
	if err != nil {
		t.Fatalf("recovered evaluation failed: %v", err)
	}
	if res2.Remaining != 7 {
		t.Errorf("expected remaining=7 from recovered Redis client, got %d", res2.Remaining)
	}
}

func TestRedisStorage_ResetAndClose(t *testing.T) {
	resetCalled := false
	mockClient := &mockRedisClient{
		delFunc: func(ctx context.Context, keys ...string) error {
			resetCalled = true
			return nil
		},
	}

	storage := NewRedisStorage(RedisStorageConfig{
		Client:            mockClient,
		FallbackOnFailure: true,
	})

	if err := storage.Reset(context.Background(), "reset-me"); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	if !resetCalled {
		t.Errorf("expected DEL called on redis client")
	}

	if err := storage.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}
