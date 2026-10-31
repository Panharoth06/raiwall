package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, addr string, opts Options) *SimpleRESPClient {
	t.Helper()
	opts.Addr = addr
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	client, err := NewRESPClient(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRESPClient_Auth(t *testing.T) {
	fake := startFakeRedis(t, "s3cret", nil)
	ctx := context.Background()

	good := newTestClient(t, fake.addr(), Options{Password: "s3cret"})
	require.NoError(t, good.Ping(ctx))
	require.EqualValues(t, 1, fake.authSuccess.Load())

	bad := newTestClient(t, fake.addr(), Options{Password: "wrong"})
	err := bad.Ping(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "WRONGPASS")
	require.GreaterOrEqual(t, fake.authFailures.Load(), int32(1))
}

func TestRESPClient_RequiresPasswordWhenServerDoes(t *testing.T) {
	fake := startFakeRedis(t, "s3cret", nil)

	// A client built without credentials never sends AUTH, so the server
	// rejects every command. The connection must stay usable for a retry
	// rather than being torn down as an I/O failure.
	anonymous := newTestClient(t, fake.addr(), Options{})
	err := anonymous.Ping(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "NOAUTH")
	require.Error(t, anonymous.Ping(context.Background()))
}

func TestRESPClient_SetGetPublish(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	client := newTestClient(t, fake.addr(), Options{})
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "key", "value", 0))
	got, err := client.Get(ctx, "key")
	require.NoError(t, err)
	require.Equal(t, "value", got)

	_, err = client.Get(ctx, "missing")
	require.ErrorIs(t, err, ErrNil)

	require.NoError(t, client.Publish(ctx, "channel", "payload"))
}

func TestRESPClient_SubscribeDeliversAndClosesOnCancel(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subscriber := newTestClient(t, fake.addr(), Options{})
	publisher := newTestClient(t, fake.addr(), Options{})

	messages, err := subscriber.Subscribe(ctx, "events")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fake.subscriberCount("events") == 1 },
		2*time.Second, 10*time.Millisecond)

	require.NoError(t, publisher.Publish(context.Background(), "events", "hello"))
	require.Equal(t, "hello", receive(t, messages, 2*time.Second))

	cancel()
	select {
	case _, ok := <-messages:
		require.False(t, ok, "subscription channel must close when the context ends")
	case <-time.After(2 * time.Second):
		t.Fatal("subscription channel did not close after cancellation")
	}
}

func TestRESPClient_SubscribeReconnectsAfterDrop(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subscriber := newTestClient(t, fake.addr(), Options{})
	publisher := newTestClient(t, fake.addr(), Options{})

	messages, err := subscriber.Subscribe(ctx, "events")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fake.subscriberCount("events") == 1 },
		2*time.Second, 10*time.Millisecond)

	fake.dropConnections()

	// The publisher's shared connection also dropped, so its first publish may
	// fail while redialing. Keep publishing until the resubscribed reader
	// receives the payload.
	require.Eventually(t, func() bool {
		if err := publisher.Publish(context.Background(), "events", "again"); err != nil {
			return false
		}
		select {
		case got := <-messages:
			return got == "again"
		default:
			return false
		}
	}, 5*time.Second, 25*time.Millisecond)
}

func TestRESPClient_KeepAliveStaysOnOneConnection(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A short command timeout proves the subscription handshake's write
	// deadline is cleared: otherwise the PING writer dies after Timeout and the
	// reader times out, forcing a reconnect every few milliseconds.
	client := newTestClient(t, fake.addr(), Options{
		Timeout:   50 * time.Millisecond,
		KeepAlive: 10 * time.Millisecond,
	})
	_, err := client.Subscribe(ctx, "idle")
	require.NoError(t, err)

	require.Eventually(t, func() bool { return fake.pings.Load() >= 10 },
		2*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 1, fake.accepted.Load(), "keep-alive must not force reconnects")
}

func TestRESPClient_TLS(t *testing.T) {
	serverTLS, caPath := selfSignedTLS(t)
	fake := startFakeRedis(t, "tls-pass", serverTLS)

	client := newTestClient(t, fake.addr(), Options{
		Password:  "tls-pass",
		TLS:       true,
		TLSCAFile: caPath,
	})
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "secure", "yes", 0))
	got, err := client.Get(ctx, "secure")
	require.NoError(t, err)
	require.Equal(t, "yes", got)
	require.GreaterOrEqual(t, fake.authSuccess.Load(), int32(1))
}

func TestRESPClient_GetMissingSnapshotIsErrNilForSubscriber(t *testing.T) {
	fake := startFakeRedis(t, "", nil)
	client := newTestClient(t, fake.addr(), Options{})

	_, err := client.Get(context.Background(), DefaultSnapshotKey)
	require.True(t, errors.Is(err, ErrNil))
}

func receive(t *testing.T, ch <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case msg, ok := <-ch:
		require.True(t, ok, "subscription channel closed unexpectedly")
		return msg
	case <-time.After(timeout):
		t.Fatal("timed out waiting for subscription message")
		return ""
	}
}
