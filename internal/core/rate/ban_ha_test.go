package rate

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeBanStorage records writes so tests can prove remote applies and
// hydration do not echo back to the shared store.
type fakeBanStorage struct {
	mu      sync.Mutex
	entries []*BanEntry
	stores  int
	removes int
	clears  int
	listErr error
}

func (f *fakeBanStorage) StoreBan(_ context.Context, entry *BanEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stores++
	f.entries = append(f.entries, entry)
	return nil
}

func (f *fakeBanStorage) RemoveBan(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	return nil
}

func (f *fakeBanStorage) ClearBans(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears++
	return nil
}

func (f *fakeBanStorage) ListBans(context.Context) ([]*BanEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]*BanEntry(nil), f.entries...), nil
}

func (f *fakeBanStorage) calls() (stores, removes, clears int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stores, f.removes, f.clears
}

func newTestBanManager(t *testing.T) (*BanManager, *fakeBanStorage, *callbackCounter) {
	t.Helper()
	storage := &fakeBanStorage{}
	counter := &callbackCounter{}
	bm := NewBanManager(nil)
	bm.SetBanStorage(storage)
	bm.SetOnBan(counter.onBan)
	bm.SetOnUnblock(counter.onUnblock)
	bm.SetOnUnblockAll(counter.onUnblockAll)
	t.Cleanup(func() { _ = bm.Close() })
	return bm, storage, counter
}

type callbackCounter struct {
	mu         sync.Mutex
	bans       int
	unblocks   int
	unblockAll int
}

func (c *callbackCounter) onBan(*BanEntry) {
	c.mu.Lock()
	c.bans++
	c.mu.Unlock()
}

func (c *callbackCounter) onUnblock(string) {
	c.mu.Lock()
	c.unblocks++
	c.mu.Unlock()
}

func (c *callbackCounter) onUnblockAll() {
	c.mu.Lock()
	c.unblockAll++
	c.mu.Unlock()
}

func (c *callbackCounter) counts() (bans, unblocks, unblockAll int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bans, c.unblocks, c.unblockAll
}

func liveEntry(key string, expiresIn time.Duration) *BanEntry {
	now := time.Now()
	return &BanEntry{
		Key:       key,
		ClientIP:  key,
		Reason:    "remote",
		BannedAt:  now,
		ExpiresAt: now.Add(expiresIn),
	}
}

func TestBanManagerHydrateLoadsUnexpiredWithoutCallbacks(t *testing.T) {
	bm, storage, counter := newTestBanManager(t)

	storage.entries = []*BanEntry{
		liveEntry("203.0.113.10", time.Hour),
		liveEntry("203.0.113.11", -time.Minute),
	}

	require.NoError(t, bm.Hydrate(context.Background()))

	banned, _ := bm.IsBanned(net.ParseIP("203.0.113.10"), "")
	require.True(t, banned)
	expired, _ := bm.IsBanned(net.ParseIP("203.0.113.11"), "")
	require.False(t, expired)
	require.Equal(t, 1, bm.Count(), "expired entries must not be hydrated")

	bans, unblocks, unblockAll := counter.counts()
	require.Zero(t, bans)
	require.Zero(t, unblocks)
	require.Zero(t, unblockAll)

	stores, _, _ := storage.calls()
	require.Zero(t, stores, "hydration must not re-store bans")
}

func TestBanManagerHydratePropagatesStorageError(t *testing.T) {
	bm, storage, _ := newTestBanManager(t)
	storage.listErr = errors.New("redis unavailable")

	require.Error(t, bm.Hydrate(context.Background()))
}

func TestBanManagerHydratePrunesBansRemovedWhileDisconnected(t *testing.T) {
	bm, storage, _ := newTestBanManager(t)
	bm.ApplyRemoteBan(liveEntry("203.0.113.70", time.Hour))

	// Shared storage no longer has the local ban: it was unblocked while this
	// replica was disconnected.
	storage.entries = []*BanEntry{liveEntry("203.0.113.71", time.Hour)}

	require.NoError(t, bm.Hydrate(context.Background()))
	require.Equal(t, 1, bm.Count(), "a missed unblock must be reconciled from storage")

	pruned, _ := bm.IsBanned(net.ParseIP("203.0.113.70"), "")
	require.False(t, pruned)
	present, _ := bm.IsBanned(net.ParseIP("203.0.113.71"), "")
	require.True(t, present)
}

func TestApplyRemoteBanSkipsStorageAndCallbacks(t *testing.T) {
	bm, storage, counter := newTestBanManager(t)

	bm.ApplyRemoteBan(liveEntry("198.51.100.7", time.Hour))
	bm.ApplyRemoteBan(liveEntry("198.51.100.8", -time.Minute))

	require.Equal(t, 1, bm.Count(), "expired remote bans must be ignored")
	banned, entry := bm.IsBanned(net.ParseIP("198.51.100.7"), "")
	require.True(t, banned)
	require.Equal(t, "198.51.100.7", entry.ClientIP)

	bans, unblocks, unblockAll := counter.counts()
	require.Zero(t, bans, "remote applies must not re-publish")
	require.Zero(t, unblocks)
	require.Zero(t, unblockAll)

	stores, removes, clears := storage.calls()
	require.Zero(t, stores, "the publishing replica already stored the ban")
	require.Zero(t, removes)
	require.Zero(t, clears)
}

func TestApplyRemoteUnblockRemovesEntriesWithoutEcho(t *testing.T) {
	bm, storage, counter := newTestBanManager(t)
	bm.ApplyRemoteBan(liveEntry("198.51.100.20", time.Hour))
	bm.ApplyRemoteBan(liveEntry("198.51.100.21", time.Hour))

	bm.ApplyRemoteUnblock("198.51.100.20")

	require.Equal(t, 1, bm.Count())
	banned, _ := bm.IsBanned(net.ParseIP("198.51.100.20"), "")
	require.False(t, banned)

	_, unblocks, _ := counter.counts()
	require.Zero(t, unblocks, "a remote unblock must not be re-published")
	_, removes, _ := storage.calls()
	require.Zero(t, removes, "the publishing replica already removed the ban")
}

func TestApplyRemoteUnblockAllClearsWithoutEcho(t *testing.T) {
	bm, storage, counter := newTestBanManager(t)
	bm.ApplyRemoteBan(liveEntry("198.51.100.30", time.Hour))
	bm.ApplyRemoteBan(liveEntry("198.51.100.31", time.Hour))

	bm.ApplyRemoteUnblockAll()

	require.Zero(t, bm.Count())
	_, _, unblockAll := counter.counts()
	require.Zero(t, unblockAll)
	_, _, clears := storage.calls()
	require.Zero(t, clears)
}
