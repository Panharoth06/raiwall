package redis

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/stretchr/testify/require"
)

// TestTwoReplicasConvergeOnBans proves the 0.3 gate: a ban created on one
// replica reaches another through Redis pub/sub without an echo, and unblock
// events remove it.
func TestTwoReplicasConvergeOnBans(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientA := newTestClient(t, fake.addr(), Options{})
	clientB := newTestClient(t, fake.addr(), Options{})
	publisherA := NewPublisher(clientA)

	bmA := rate.NewBanManager(nil)
	defer bmA.Close()
	bmA.SetOnBan(func(entry *rate.BanEntry) {
		_ = publisherA.PublishBan(ctx, entry)
	})

	bmB := rate.NewBanManager(nil)
	defer bmB.Close()
	subscriberB := NewSubscriber(SubscriberConfig{
		Client:       clientB,
		PollInterval: time.Hour, // isolate pub/sub from the poll fallback
		OnBan:        bmB.ApplyRemoteBan,
		OnUnblock:    bmB.ApplyRemoteUnblock,
		OnUnblockAll: bmB.ApplyRemoteUnblockAll,
	})
	require.NoError(t, subscriberB.Start(ctx))
	defer subscriberB.Stop()

	require.Eventually(t, func() bool {
		return fake.subscriberCount(DefaultClusterChannel) == 1
	}, 2*time.Second, 10*time.Millisecond)

	ip := net.ParseIP("198.51.100.90")
	bmA.Ban(ip, "ja4_converge", time.Hour, "tier2_attack")

	require.Eventually(t, func() bool {
		banned, _ := bmB.IsBanned(ip, "ja4_converge")
		return banned
	}, 3*time.Second, 10*time.Millisecond, "replica B did not receive the ban")

	// The receiving replica must not republish: exactly one PUBLISH was sent.
	require.Eventually(t, func() bool { return fake.published.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, 1, fake.published.Load(), "remote apply echoed the ban")

	require.NoError(t, publisherA.PublishUnblock(ctx, "198.51.100.90"))
	require.Eventually(t, func() bool {
		banned, _ := bmB.IsBanned(ip, "ja4_converge")
		return !banned
	}, 3*time.Second, 10*time.Millisecond, "replica B did not apply the unblock")

	bmA.Ban(ip, "", time.Hour, "tier2_attack")
	require.Eventually(t, func() bool { return bmB.Count() == 1 }, 3*time.Second, 10*time.Millisecond)

	require.NoError(t, publisherA.PublishUnblockAll(ctx))
	require.Eventually(t, func() bool { return bmB.Count() == 0 }, 3*time.Second, 10*time.Millisecond,
		"replica B did not apply unblock-all")
}

// TestBanManagerHydratesFromRedisStorage simulates a restart: a fresh manager
// loads the bans the previous process left in shared storage, skipping expired
// entries and without re-storing them.
func TestBanManagerHydratesFromRedisStorage(t *testing.T) {
	var stored []string
	var writes int
	client := &mockRedisClient{evalFunc: func(_ context.Context, script string, _ []string, args ...any) (any, error) {
		switch script {
		case storeBanScript:
			writes++
			stored = append(stored, args[0].(string))
			return int64(1), nil
		case listBansScript:
			out := make([]any, len(stored))
			for i, raw := range stored {
				out[i] = raw
			}
			return out, nil
		default:
			return int64(1), nil
		}
	}}

	storage := NewRedisBanStorage(client, "test:bans:")
	now := time.Now()
	require.NoError(t, storage.StoreBan(context.Background(), &rate.BanEntry{
		Key: "203.0.113.60", ClientIP: "203.0.113.60", Duration: time.Hour, ExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, storage.StoreBan(context.Background(), &rate.BanEntry{
		Key: "203.0.113.61", ClientIP: "203.0.113.61", Duration: time.Hour, ExpiresAt: now.Add(-time.Hour),
	}))
	writesBefore := writes

	bm := rate.NewBanManager(nil)
	defer bm.Close()
	bm.SetBanStorage(storage)

	require.NoError(t, bm.Hydrate(context.Background()))
	require.Equal(t, 1, bm.Count(), "expired stored bans must not be hydrated")
	banned, entry := bm.IsBanned(net.ParseIP("203.0.113.60"), "")
	require.True(t, banned)
	require.Equal(t, "203.0.113.60", entry.ClientIP)
	require.Equal(t, writesBefore, writes, "hydration must not write bans back")
}
