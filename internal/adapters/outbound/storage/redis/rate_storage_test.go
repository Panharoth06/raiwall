package redis

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/rate"
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
			return []any{int64(1), int64(4), int64(0), int64(250)}, nil
		},
	}

	storage := NewRedisStorage(RedisStorageConfig{
		Client:            mockClient,
		KeyPrefix:         "test:rate:",
		FallbackOnFailure: true,
	})
	defer storage.Close()

	cfg := rate.RateLimitConfig{Rate: 10, Period: time.Second, Burst: 5}
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

	cfg := rate.RateLimitConfig{Rate: 2, Period: time.Second, Burst: 0}
	ctx := context.Background()

	res1, err := storage.EvalGCRA(ctx, "fallback-key", cfg, 1, time.Now())
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if !res1.Allowed {
		t.Fatalf("1st request should be allowed in fallback")
	}

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
		Client:            nil,
		FallbackOnFailure: true,
	})
	defer storage.Close()

	cfg := rate.RateLimitConfig{Rate: 10, Period: time.Second, Burst: 2}
	ctx := context.Background()

	res, err := storage.EvalGCRA(ctx, "recover-key", cfg, 1, time.Now())
	if err != nil || !res.Allowed {
		t.Fatalf("fallback failed: %v", err)
	}

	recoveredClient := &mockRedisClient{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			return []any{int64(1), int64(7), int64(0), int64(500)}, nil
		},
	}
	storage.SetClient(recoveredClient)

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

func TestSimpleRESPClient_Pipe(t *testing.T) {
	var connMu sync.Mutex
	var activeServerConns []net.Conn

	dialer := func(network, addr string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		connMu.Lock()
		activeServerConns = append(activeServerConns, serverConn)
		connMu.Unlock()

		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				cmd := string(buf[:n])
				if strings.Contains(cmd, "PING") {
					_, _ = c.Write([]byte("+PONG\r\n"))
				} else if strings.Contains(cmd, "EVAL") {
					_, _ = c.Write([]byte("*4\r\n:1\r\n:5\r\n:0\r\n:100\r\n"))
				} else if strings.Contains(cmd, "DEL") {
					_, _ = c.Write([]byte(":1\r\n"))
				} else if strings.Contains(cmd, "DROP") {
					return
				}
			}
		}(serverConn)

		return clientConn, nil
	}

	client := NewSimpleRESPClient("in-memory:6379", 500*time.Millisecond)
	client.SetDialer(dialer)
	defer func() {
		client.Close()
		connMu.Lock()
		for _, sc := range activeServerConns {
			_ = sc.Close()
		}
		connMu.Unlock()
	}()

	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	res, err := client.Eval(context.Background(), "return {1, 5, 0, 100}", []string{"k1"}, 10)
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	slice, ok := res.([]any)
	if !ok || len(slice) != 4 {
		t.Fatalf("expected 4 elements in eval result, got %v", res)
	}

	if err := client.Del(context.Background(), "k1"); err != nil {
		t.Fatalf("del failed: %v", err)
	}

	_ = client.Close()
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("reconnect ping failed: %v", err)
	}
}

func TestSimpleRESPClient_RealTCPAndReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping real TCP test: net.Listen failed: %v", err)
		return
	}
	defer ln.Close()

	serverClosed := make(chan struct{})
	go func() {
		defer close(serverClosed)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					cmd := string(buf[:n])
					if strings.Contains(cmd, "PING") {
						_, _ = c.Write([]byte("+PONG\r\n"))
					} else if strings.Contains(cmd, "EVAL") {
						_, _ = c.Write([]byte("*4\r\n:1\r\n:5\r\n:0\r\n:100\r\n"))
					} else if strings.Contains(cmd, "DEL") {
						_, _ = c.Write([]byte(":1\r\n"))
					} else if strings.Contains(cmd, "DROP") {
						return
					}
				}
			}(conn)
		}
	}()

	client := NewSimpleRESPClient(ln.Addr().String(), 500*time.Millisecond)
	defer client.Close()

	if err := client.Ping(context.Background()); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
			t.Skipf("skipping TCP ping due to environment permissions: %v", err)
			return
		}
		t.Fatalf("ping failed: %v", err)
	}

	res, err := client.Eval(context.Background(), "return {1, 5, 0, 100}", []string{"k1"}, 10)
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	slice, ok := res.([]any)
	if !ok || len(slice) != 4 {
		t.Fatalf("expected 4 elements in eval result, got %v", res)
	}

	if err := client.Del(context.Background(), "k1"); err != nil {
		t.Fatalf("del failed: %v", err)
	}
}
