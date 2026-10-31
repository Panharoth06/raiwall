package rate

import (
	"context"
	"time"
)

// Hydrate reconciles local bans with the shared storage. It runs at startup
// and after every reconnect, so bans and unblocks that happened while this
// replica was disconnected converge. The shared store is authoritative: a ban
// created while Redis was unreachable exists only locally and is dropped on
// reconnect. Hydration does not write back or fire callbacks, which would
// echo every ban around the cluster.
func (bm *BanManager) Hydrate(ctx context.Context) error {
	if bm == nil {
		return nil
	}

	bm.mu.RLock()
	storage := bm.banStorage
	bm.mu.RUnlock()
	if storage == nil {
		return nil
	}

	entries, err := storage.ListBans(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	stored := make(map[string]*BanEntry, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.Key == "" || !now.Before(entry.ExpiresAt) {
			continue
		}
		stored[entry.Key] = entry
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()
	for key := range bm.entries {
		if _, ok := stored[key]; !ok {
			delete(bm.entries, key)
		}
	}
	for key, entry := range stored {
		bm.entries[key] = entry
	}
	return nil
}

// ApplyRemoteBan installs a ban published by another replica. It must not call
// onBan or touch ban storage: the publishing replica already did both, and
// re-emitting would loop the event around the cluster.
func (bm *BanManager) ApplyRemoteBan(entry *BanEntry) {
	if bm == nil || entry == nil || entry.Key == "" {
		return
	}
	if !time.Now().Before(entry.ExpiresAt) {
		return
	}
	bm.mu.Lock()
	bm.entries[entry.Key] = entry
	bm.mu.Unlock()
}

// ApplyRemoteUnblock removes a ban published by another replica, matching the
// same key, client IP, and JA4 rules as Release, without echoing the event.
func (bm *BanManager) ApplyRemoteUnblock(target string) {
	if bm == nil || target == "" {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.entries, target)
	for key, entry := range bm.entries {
		if entry.ClientIP == target || entry.Key == target || entry.JA4 == target {
			delete(bm.entries, key)
		}
	}
}

// ApplyRemoteUnblockAll clears local bans after another replica's emergency
// unblock-all, without re-publishing or re-clearing shared storage.
func (bm *BanManager) ApplyRemoteUnblockAll() {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	bm.entries = make(map[string]*BanEntry)
	bm.mu.Unlock()
}
