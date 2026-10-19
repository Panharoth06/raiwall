package cluster

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestCluster_PublishAndSubscribe(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial active snapshot on worker: Version 1
	snap1 := config.NewConfigSnapshot(1, config.ModeDefense, []*config.AppConfig{
		{
			ID:        "app-v1",
			Name:      "App V1",
			Hostnames: []string{"v1.example.com"},
			Mode:      config.ModeDefense,
			Upstreams: []config.UpstreamTarget{{Dial: "127.0.0.1:8001"}},
		},
	})
	config.StoreSnapshot(snap1)

	// Start subscriber on worker
	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 50 * time.Millisecond,
	})
	err := sub.Start(ctx)
	require.NoError(t, err)
	defer sub.Stop()

	require.Equal(t, uint64(1), sub.LastAppliedVersion())

	// Master publishes Version 2
	publisher := NewPublisher(mockRedis)
	snap2 := config.NewConfigSnapshot(2, config.ModeDefense, []*config.AppConfig{
		{
			ID:        "app-v2",
			Name:      "App V2",
			Hostnames: []string{"v2.example.com"},
			Mode:      config.ModeDefense,
			Upstreams: []config.UpstreamTarget{{Dial: "127.0.0.1:8002"}},
		},
	})

	err = publisher.PublishSnapshot(ctx, snap2, "master-admin")
	require.NoError(t, err)

	// Worker should receive notification and apply atomically
	require.Eventually(t, func() bool {
		return sub.LastAppliedVersion() == 2 && config.GetActiveSnapshot().Version == 2
	}, 1*time.Second, 10*time.Millisecond)

	active := config.GetActiveSnapshot()
	_, found := active.GetAppForHost("v2.example.com")
	require.True(t, found)
}

func TestCluster_ReconnectReSync(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Base snapshot: Version 1
	snap1 := config.NewConfigSnapshot(1, config.ModeDefense, nil)
	config.StoreSnapshot(snap1)

	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 50 * time.Millisecond,
	})
	err := sub.Start(ctx)
	require.NoError(t, err)
	defer sub.Stop()

	// Simulate missed Pub/Sub: write directly to Redis cache without publishing event
	snap3 := config.NewConfigSnapshot(3, config.ModeDefense, []*config.AppConfig{
		{
			ID:        "app-v3",
			Name:      "App V3",
			Hostnames: []string{"v3.example.com"},
			Mode:      config.ModeDefense,
			Upstreams: []config.UpstreamTarget{{Dial: "127.0.0.1:8003"}},
		},
	})
	publisher := NewPublisher(mockRedis)
	snapData, _ := json.Marshal(snap3)
	_ = mockRedis.Set(ctx, publisher.snapshotKey, string(snapData), time.Hour)

	// Periodic poll synchronizer should discover Version 3 and heal drift
	require.Eventually(t, func() bool {
		return sub.LastAppliedVersion() == 3 && config.GetActiveSnapshot().Version == 3
	}, 1*time.Second, 10*time.Millisecond)

	active := config.GetActiveSnapshot()
	require.Equal(t, uint64(3), active.Version)
	_, found := active.GetAppForHost("v3.example.com")
	require.True(t, found)
}

func TestCluster_GracefulFallbackOnRedisError(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx := context.Background()

	// Active snapshot Version 10
	snap10 := config.NewConfigSnapshot(10, config.ModeDefense, []*config.AppConfig{
		{
			ID:        "app-v10",
			Name:      "App V10",
			Hostnames: []string{"v10.example.com"},
			Mode:      config.ModeDefense,
			Upstreams: []config.UpstreamTarget{{Dial: "127.0.0.1:8010"}},
		},
	})
	config.StoreSnapshot(snap10)

	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 10 * time.Millisecond,
	})

	// Simulate Redis failing
	mockRedis.SetFailPing(true)

	// SyncLatest should not fail or panic
	err := sub.SyncLatest(ctx)
	require.NoError(t, err)

	// Data plane snapshot continues serving unaffected
	active := config.GetActiveSnapshot()
	require.Equal(t, uint64(10), active.Version)
	_, found := active.GetAppForHost("v10.example.com")
	require.True(t, found)
}
