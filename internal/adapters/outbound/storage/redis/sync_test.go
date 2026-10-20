package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestCluster_PublishAndSubscribe(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap1 := control.NewConfigSnapshot(1, control.ModeDefense, []*control.AppConfig{
		{
			ID:        "app-v1",
			Name:      "App V1",
			Hostnames: []string{"v1.example.com"},
			Mode:      control.ModeDefense,
			Upstreams: []control.UpstreamTarget{{Dial: "127.0.0.1:8001"}},
		},
	})
	control.StoreSnapshot(snap1)

	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 50 * time.Millisecond,
	})
	err := sub.Start(ctx)
	require.NoError(t, err)
	defer sub.Stop()

	require.Equal(t, uint64(1), sub.LastAppliedVersion())

	publisher := NewPublisher(mockRedis)
	snap2 := control.NewConfigSnapshot(2, control.ModeDefense, []*control.AppConfig{
		{
			ID:        "app-v2",
			Name:      "App V2",
			Hostnames: []string{"v2.example.com"},
			Mode:      control.ModeDefense,
			Upstreams: []control.UpstreamTarget{{Dial: "127.0.0.1:8002"}},
		},
	})

	err = publisher.PublishSnapshot(ctx, snap2, "master-admin")
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return sub.LastAppliedVersion() == 2 && control.GetActiveSnapshot().Version == 2
	}, 1*time.Second, 10*time.Millisecond)

	active := control.GetActiveSnapshot()
	_, found := active.GetAppForHost("v2.example.com")
	require.True(t, found)
}

func TestCluster_ReconnectReSync(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap1 := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	control.StoreSnapshot(snap1)

	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 50 * time.Millisecond,
	})
	err := sub.Start(ctx)
	require.NoError(t, err)
	defer sub.Stop()

	snap3 := control.NewConfigSnapshot(3, control.ModeDefense, []*control.AppConfig{
		{
			ID:        "app-v3",
			Name:      "App V3",
			Hostnames: []string{"v3.example.com"},
			Mode:      control.ModeDefense,
			Upstreams: []control.UpstreamTarget{{Dial: "127.0.0.1:8003"}},
		},
	})
	publisher := NewPublisher(mockRedis)
	snapData, _ := json.Marshal(snap3)
	_ = mockRedis.Set(ctx, publisher.snapshotKey, string(snapData), time.Hour)

	require.Eventually(t, func() bool {
		return sub.LastAppliedVersion() == 3 && control.GetActiveSnapshot().Version == 3
	}, 1*time.Second, 10*time.Millisecond)

	active := control.GetActiveSnapshot()
	require.Equal(t, uint64(3), active.Version)
	_, found := active.GetAppForHost("v3.example.com")
	require.True(t, found)
}

func TestCluster_GracefulFallbackOnRedisError(t *testing.T) {
	mockRedis := NewMockRedisClient()
	defer mockRedis.Close()

	ctx := context.Background()

	snap10 := control.NewConfigSnapshot(10, control.ModeDefense, []*control.AppConfig{
		{
			ID:        "app-v10",
			Name:      "App V10",
			Hostnames: []string{"v10.example.com"},
			Mode:      control.ModeDefense,
			Upstreams: []control.UpstreamTarget{{Dial: "127.0.0.1:8010"}},
		},
	})
	control.StoreSnapshot(snap10)

	sub := NewSubscriber(SubscriberConfig{
		Client:       mockRedis,
		PollInterval: 10 * time.Millisecond,
	})

	mockRedis.SetFailPing(true)

	err := sub.SyncLatest(ctx)
	require.NoError(t, err)

	active := control.GetActiveSnapshot()
	require.Equal(t, uint64(10), active.Version)
	_, found := active.GetAppForHost("v10.example.com")
	require.True(t, found)
}
