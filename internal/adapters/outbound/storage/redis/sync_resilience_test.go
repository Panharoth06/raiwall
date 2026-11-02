package redis

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/stretchr/testify/require"
)

// flakySubscribeClient fails the first N Subscribe calls, then delegates to
// the in-memory mock. The command path is unaffected.
type flakySubscribeClient struct {
	*MockRedisClient
	failures atomic.Int32
	calls    atomic.Int32
}

func (c *flakySubscribeClient) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	c.calls.Add(1)
	if c.failures.Add(-1) >= 0 {
		return nil, errors.New("redis: connection refused")
	}
	return c.MockRedisClient.Subscribe(ctx, channel)
}

func TestSubscriberRetriesSubscribeAfterInitialFailure(t *testing.T) {
	mock := NewMockRedisClient()
	defer mock.Close()
	flaky := &flakySubscribeClient{MockRedisClient: mock}
	flaky.failures.Store(2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	banned := make(chan string, 4)
	sub := NewSubscriber(SubscriberConfig{
		Client:       flaky,
		PollInterval: time.Hour, // keep the poll fallback out of this test
		OnBan:        func(entry *rate.BanEntry) { banned <- entry.Key },
	})

	require.NoError(t, sub.Start(ctx), "a Redis outage at startup must not fail provisioning")
	defer sub.Stop()

	require.Eventually(t, func() bool { return flaky.calls.Load() >= 3 },
		3*time.Second, 20*time.Millisecond, "subscriber must retry subscribing")

	// Prove the retried subscription is live by broadcasting through it.
	pub := NewPublisher(mock)
	require.NoError(t, pub.PublishBan(ctx, &rate.BanEntry{Key: "203.0.113.99", ClientIP: "203.0.113.99", ExpiresAt: time.Now().Add(time.Hour)}))
	select {
	case key := <-banned:
		require.Equal(t, "203.0.113.99", key)
	case <-time.After(3 * time.Second):
		t.Fatal("ban was not delivered after the subscription recovered")
	}
}

func TestSubscriberRemoteApplyRunsDeployHooks(t *testing.T) {
	previous := control.GetActiveSnapshot()
	t.Cleanup(func() { control.StoreSnapshot(previous) })

	control.StoreSnapshot(control.NewConfigSnapshot(1, control.ModeDefense, nil))

	hooks := make(chan uint64, 8)
	control.RegisterDeployHook(func(_ context.Context, snap *control.ConfigSnapshot) {
		select {
		case hooks <- snap.Version:
		default:
		}
	})

	mock := NewMockRedisClient()
	defer mock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := NewSubscriber(SubscriberConfig{Client: mock, PollInterval: time.Hour})
	require.NoError(t, sub.Start(ctx))
	defer sub.Stop()

	require.True(t, mock.WaitForSubscribers(DefaultClusterChannel, 1, 2*time.Second), "subscriber should be registered")

	pub := NewPublisher(mock)
	require.NoError(t, pub.PublishSnapshot(ctx, control.NewConfigSnapshot(2, control.ModeDefense, nil), "peer"))

	select {
	case version := <-hooks:
		require.Equal(t, uint64(2), version)
	case <-time.After(3 * time.Second):
		t.Fatal("remote apply did not run deploy hooks")
	}

	require.Equal(t, uint64(2), control.GetActiveSnapshot().Version)
	require.Equal(t, uint64(2), sub.LastAppliedVersion())
	require.Equal(t, uint64(2), control.RemoteAppliedStatus().AppliedVersion)
}

func TestRESPClientNotifiesOnReconnect(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var connected atomic.Int32
	client := newTestClient(t, fake.addr(), Options{OnReconnect: func() { connected.Add(1) }})
	_, err := client.Subscribe(ctx, "events")
	require.NoError(t, err)

	require.Eventually(t, func() bool { return connected.Load() >= 1 },
		2*time.Second, 10*time.Millisecond, "the first subscribe must notify")

	fake.dropConnections()
	require.Eventually(t, func() bool { return connected.Load() >= 2 },
		3*time.Second, 10*time.Millisecond, "a transparent reconnect must notify")
}

// A client that closes its subscription channel (rather than reconnecting
// internally) forces the subscriber to resubscribe; OnConnected must run again.
func TestSubscriberRunsOnConnectedAfterResubscribe(t *testing.T) {
	mock := NewMockRedisClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var connected atomic.Int32
	sub := NewSubscriber(SubscriberConfig{
		Client:       mock,
		PollInterval: time.Hour,
		OnConnected:  func() { connected.Add(1) },
	})
	require.NoError(t, sub.Start(ctx))
	defer sub.Stop()

	require.Eventually(t, func() bool { return connected.Load() >= 1 },
		2*time.Second, 10*time.Millisecond)

	mock.Close()
	require.Eventually(t, func() bool { return connected.Load() >= 2 },
		3*time.Second, 10*time.Millisecond, "OnConnected must run after a resubscribe")
}

func TestPublisherUsesConfiguredChannel(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bans := make(chan string, 1)
	sub := NewSubscriber(SubscriberConfig{
		Client:       newTestClient(t, fake.addr(), Options{}),
		Channel:      "custom:events",
		PollInterval: time.Hour,
		OnBan:        func(entry *rate.BanEntry) { bans <- entry.Key },
	})
	require.NoError(t, sub.Start(ctx))
	defer sub.Stop()

	require.Eventually(t, func() bool { return fake.subscriberCount("custom:events") == 1 },
		2*time.Second, 10*time.Millisecond)

	publisher := NewPublisher(newTestClient(t, fake.addr(), Options{}))
	publisher.SetChannel("custom:events")
	require.NoError(t, publisher.PublishBan(ctx, &rate.BanEntry{
		Key: "203.0.113.120", ClientIP: "203.0.113.120", ExpiresAt: time.Now().Add(time.Hour),
	}))

	select {
	case key := <-bans:
		require.Equal(t, "203.0.113.120", key)
	case <-time.After(3 * time.Second):
		t.Fatal("publisher ignored the configured cluster channel")
	}
}

func TestSubscriberIgnoresMissingSnapshot(t *testing.T) {
	mock := NewMockRedisClient()
	defer mock.Close()

	sub := NewSubscriber(SubscriberConfig{Client: mock, PollInterval: time.Hour})
	require.NoError(t, sub.SyncLatest(context.Background()))
}

// Keep the sync package's race guard honest: two subscribers sharing one mock
// must not interfere when the same notification is broadcast.
func TestSubscriberMultipleReplicasConverge(t *testing.T) {
	previous := control.GetActiveSnapshot()
	t.Cleanup(func() { control.StoreSnapshot(previous) })
	control.StoreSnapshot(control.NewConfigSnapshot(1, control.ModeDefense, nil))

	mock := NewMockRedisClient()
	defer mock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subs := make([]*Subscriber, 2)
	for i := range subs {
		subs[i] = NewSubscriber(SubscriberConfig{Client: mock, PollInterval: time.Hour})
		require.NoError(t, subs[i].Start(ctx))
	}
	t.Cleanup(func() {
		for _, s := range subs {
			s.Stop()
		}
	})

	require.True(t, mock.WaitForSubscribers(DefaultClusterChannel, 2, 2*time.Second), "both subscribers should be registered")

	pub := NewPublisher(mock)
	require.NoError(t, pub.PublishSnapshot(ctx, control.NewConfigSnapshot(4, control.ModeDefense, nil), "peer"))

	require.Eventually(t, func() bool {
		return subs[0].LastAppliedVersion() == 4 && subs[1].LastAppliedVersion() == 4
	}, 3*time.Second, 10*time.Millisecond)
}
