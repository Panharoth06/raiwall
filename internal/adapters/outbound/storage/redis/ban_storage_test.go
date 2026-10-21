package redis

import (
	"context"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/rate"
)

func TestRedisBanStorage_Fallback(t *testing.T) {
	storage := NewRedisBanStorage(nil, "test:bans:")

	ctx := context.Background()
	entry1 := &rate.BanEntry{
		Key:              "198.51.100.1",
		ClientIP:         "198.51.100.1",
		Reason:           "tier1_flood",
		Duration:         time.Hour,
		RemainingSeconds: 3600,
		BannedAt:         time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	entry2 := &rate.BanEntry{
		Key:              "198.51.100.2",
		ClientIP:         "198.51.100.2",
		Reason:           "tier2_sqli",
		Duration:         time.Hour,
		RemainingSeconds: 3600,
		BannedAt:         time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
	}

	if err := storage.StoreBan(ctx, entry1); err != nil {
		t.Fatalf("failed to store ban 1: %v", err)
	}
	if err := storage.StoreBan(ctx, entry2); err != nil {
		t.Fatalf("failed to store ban 2: %v", err)
	}

	bans, err := storage.ListBans(ctx)
	if err != nil {
		t.Fatalf("failed to list bans: %v", err)
	}
	if len(bans) != 2 {
		t.Fatalf("expected 2 bans, got %d", len(bans))
	}

	// Remove single ban
	if err := storage.RemoveBan(ctx, "198.51.100.1"); err != nil {
		t.Fatalf("failed to remove ban: %v", err)
	}
	bansAfter, err := storage.ListBans(ctx)
	if err != nil {
		t.Fatalf("failed to list bans: %v", err)
	}
	if len(bansAfter) != 1 || bansAfter[0].Key != "198.51.100.2" {
		t.Fatalf("expected 1 remaining ban for 198.51.100.2, got: %+v", bansAfter)
	}

	// Clear all bans
	if err := storage.ClearBans(ctx); err != nil {
		t.Fatalf("failed to clear bans: %v", err)
	}
	bansCleared, err := storage.ListBans(ctx)
	if err != nil {
		t.Fatalf("failed to list bans: %v", err)
	}
	if len(bansCleared) != 0 {
		t.Fatalf("expected 0 bans after clear, got %d", len(bansCleared))
	}
}

func TestRedisBanStorage_WithClient(t *testing.T) {
	storedJSON := ""
	mockClient := &mockRedisClient{
		evalFunc: func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
			if script == storeBanScript {
				storedJSON = args[0].(string)
				return int64(1), nil
			}
			if script == listBansScript {
				if storedJSON == "" {
					return []any{}, nil
				}
				return []any{storedJSON}, nil
			}
			if script == removeBanScript || script == clearBansScript {
				storedJSON = ""
				return int64(1), nil
			}
			return int64(1), nil
		},
	}

	storage := NewRedisBanStorage(mockClient, "test:bans:")
	ctx := context.Background()
	entry := &rate.BanEntry{
		Key:              "198.51.100.55",
		ClientIP:         "198.51.100.55",
		Reason:           "tier3_scanner",
		Duration:         time.Hour,
		RemainingSeconds: 3600,
		BannedAt:         time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
	}

	if err := storage.StoreBan(ctx, entry); err != nil {
		t.Fatalf("failed to store ban: %v", err)
	}

	bans, err := storage.ListBans(ctx)
	if err != nil {
		t.Fatalf("failed to list bans: %v", err)
	}
	if len(bans) != 1 || bans[0].Key != "198.51.100.55" {
		t.Fatalf("expected 1 ban, got %+v", bans)
	}

	if err := storage.ClearBans(ctx); err != nil {
		t.Fatalf("failed to clear bans: %v", err)
	}
	bansAfter, _ := storage.ListBans(ctx)
	if len(bansAfter) != 0 {
		t.Fatalf("expected 0 bans, got %d", len(bansAfter))
	}
}

func TestClusterUnblockBroadcast(t *testing.T) {
	mockRedis := NewMockRedisClient()
	pub := NewPublisher(mockRedis)

	unblockCh := make(chan string, 5)
	unblockAllCh := make(chan struct{}, 5)

	sub := NewSubscriber(SubscriberConfig{
		Client:  mockRedis,
		Channel: DefaultClusterChannel,
		OnUnblock: func(target string) {
			unblockCh <- target
		},
		OnUnblockAll: func() {
			unblockAllCh <- struct{}{}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sub.Start(ctx); err != nil {
		t.Fatalf("failed to start subscriber: %v", err)
	}
	defer sub.Stop()

	// Wait briefly for subscription to register
	time.Sleep(20 * time.Millisecond)

	// Publish single unblock
	if err := pub.PublishUnblock(ctx, "203.0.113.88"); err != nil {
		t.Fatalf("failed to publish unblock: %v", err)
	}

	select {
	case target := <-unblockCh:
		if target != "203.0.113.88" {
			t.Errorf("expected target 203.0.113.88, got %q", target)
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("timeout waiting for unblock event")
	}

	// Publish unblock all
	if err := pub.PublishUnblockAll(ctx); err != nil {
		t.Fatalf("failed to publish unblock-all: %v", err)
	}

	select {
	case <-unblockAllCh:
		// success
	case <-time.After(200 * time.Millisecond):
		t.Errorf("timeout waiting for unblock-all event")
	}

	// Publish active ban
	banCh := make(chan *rate.BanEntry, 5)
	sub2 := NewSubscriber(SubscriberConfig{
		Client:  mockRedis,
		Channel: DefaultClusterChannel,
		OnBan: func(entry *rate.BanEntry) {
			banCh <- entry
		},
	})
	if err := sub2.Start(ctx); err != nil {
		t.Fatalf("failed to start sub2: %v", err)
	}
	defer sub2.Stop()
	time.Sleep(20 * time.Millisecond)

	banEntry := &rate.BanEntry{
		Key:      "198.51.100.99",
		ClientIP: "198.51.100.99",
		Reason:   "cluster_test",
	}
	if err := pub.PublishBan(ctx, banEntry); err != nil {
		t.Fatalf("failed to publish ban: %v", err)
	}

	select {
	case b := <-banCh:
		if b.Key != "198.51.100.99" {
			t.Errorf("expected ban key 198.51.100.99, got %q", b.Key)
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("timeout waiting for ban broadcast event")
	}
}

func TestRedisBanStorage_BoundaryUnblock(t *testing.T) {
	storage := NewRedisBanStorage(nil, "test:bans:boundary:")
	ctx := context.Background()

	// Store 198.51.100.1, 198.51.100.10, and composite 198.51.100.1|ja4_abc
	e1 := &rate.BanEntry{Key: "198.51.100.1", ClientIP: "198.51.100.1", ExpiresAt: time.Now().Add(time.Hour)}
	e2 := &rate.BanEntry{Key: "198.51.100.10", ClientIP: "198.51.100.10", ExpiresAt: time.Now().Add(time.Hour)}
	e3 := &rate.BanEntry{Key: "198.51.100.1|ja4_abc", ClientIP: "198.51.100.1", JA4: "ja4_abc", ExpiresAt: time.Now().Add(time.Hour)}

	_ = storage.StoreBan(ctx, e1)
	_ = storage.StoreBan(ctx, e2)
	_ = storage.StoreBan(ctx, e3)

	bans, _ := storage.ListBans(ctx)
	if len(bans) != 3 {
		t.Fatalf("expected 3 bans, got %d", len(bans))
	}

	// Remove 198.51.100.1: e1 and e3 must be deleted, e2 (198.51.100.10) MUST remain
	_ = storage.RemoveBan(ctx, "198.51.100.1")

	remaining, _ := storage.ListBans(ctx)
	if len(remaining) != 1 {
		t.Fatalf("expected exactly 1 remaining ban, got %d: %+v", len(remaining), remaining)
	}
	if remaining[0].Key != "198.51.100.10" {
		t.Errorf("expected 198.51.100.10 to remain, got %q", remaining[0].Key)
	}

	// Remove by JA4 on composite ban
	e4 := &rate.BanEntry{Key: "198.51.100.20|ja4_xyz", ClientIP: "198.51.100.20", JA4: "ja4_xyz", ExpiresAt: time.Now().Add(time.Hour)}
	_ = storage.StoreBan(ctx, e4)
	_ = storage.RemoveBan(ctx, "ja4_xyz")
	remaining2, _ := storage.ListBans(ctx)
	if len(remaining2) != 1 || remaining2[0].Key != "198.51.100.10" {
		t.Errorf("expected composite ban removed when unblocking JA4")
	}
}
