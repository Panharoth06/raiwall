package rate

import (
	"context"
	"sort"
	"time"
)

// SetRateStorage configures the distributed storage layer for ban eviction.
func (bm *BanManager) SetRateStorage(st RateStorage) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.storage = st
}

// SetBanStorage configures the persistent or distributed ban storage.
func (bm *BanManager) SetBanStorage(bs BanStorage) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.banStorage = bs
}

// SetOnBan sets a callback invoked when an IP or composite key is banned.
func (bm *BanManager) SetOnBan(fn func(*BanEntry)) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.onBan = fn
}

// SetOnUnblock sets a callback invoked when an IP or ban key is unblocked.
func (bm *BanManager) SetOnUnblock(fn func(string)) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.onUnblock = fn
}

// SetOnUnblockAll sets a callback invoked when emergency unblock all is triggered.
func (bm *BanManager) SetOnUnblockAll(fn func()) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.onUnblockAll = fn
}

// AddEntry stores a ban entry in local memory (e.g. from cluster sync).
func (bm *BanManager) AddEntry(entry *BanEntry) {
	if bm == nil || entry == nil || entry.Key == "" {
		return
	}
	bm.mu.Lock()
	bm.entries[entry.Key] = entry
	bm.mu.Unlock()
}

// ListBans returns all currently active, non-expired bans with calculated remaining duration.
func (bm *BanManager) ListBans() []*BanEntry {
	if bm == nil {
		return nil
	}
	bm.mu.RLock()
	bs := bm.banStorage
	now := time.Now()
	res := make([]*BanEntry, 0, len(bm.entries))
	seen := make(map[string]bool, len(bm.entries))
	for _, e := range bm.entries {
		if now.Before(e.ExpiresAt) {
			clone := *e
			clone.RemainingSeconds = int64(time.Until(e.ExpiresAt).Seconds())
			if clone.RemainingSeconds < 0 {
				clone.RemainingSeconds = 0
			}
			res = append(res, &clone)
			seen[clone.Key] = true
		}
	}
	bm.mu.RUnlock()

	if bs != nil {
		if extBans, err := bs.ListBans(context.Background()); err == nil {
			for _, eb := range extBans {
				if eb != nil && !seen[eb.Key] && now.Before(eb.ExpiresAt) {
					clone := *eb
					clone.RemainingSeconds = int64(time.Until(eb.ExpiresAt).Seconds())
					if clone.RemainingSeconds < 0 {
						clone.RemainingSeconds = 0
					}
					res = append(res, &clone)
					seen[clone.Key] = true
				}
			}
		}
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].BannedAt.After(res[j].BannedAt)
	})
	return res
}

// Release removes an active ban by key, IP, or JA4 and evicts from underlying rate storage and ban storage.
func (bm *BanManager) Release(keyOrIP string) bool {
	if bm == nil || keyOrIP == "" {
		return false
	}
	bm.mu.Lock()
	found := false
	if _, ok := bm.entries[keyOrIP]; ok {
		delete(bm.entries, keyOrIP)
		found = true
	}
	for k, e := range bm.entries {
		if e.ClientIP == keyOrIP || e.Key == keyOrIP || e.JA4 == keyOrIP {
			delete(bm.entries, k)
			found = true
		}
	}
	st := bm.storage
	bs := bm.banStorage
	cb := bm.onUnblock
	bm.mu.Unlock()

	if bs != nil {
		if err := bs.RemoveBan(context.Background(), keyOrIP); err == nil {
			found = true
		}
	}
	if st != nil {
		_ = st.Reset(context.Background(), keyOrIP)
	}
	if cb != nil {
		cb(keyOrIP)
	}
	return found
}

// ReleaseAll purges the entire active ban registry, clears ban storage, and invokes unblock broadcast callbacks.
func (bm *BanManager) ReleaseAll() int {
	if bm == nil {
		return 0
	}
	bm.mu.Lock()
	count := len(bm.entries)
	bm.entries = make(map[string]*BanEntry)
	bs := bm.banStorage
	cb := bm.onUnblockAll
	bm.mu.Unlock()

	if bs != nil {
		_ = bs.ClearBans(context.Background())
	}
	if cb != nil {
		cb()
	}
	return count
}

// Clear removes all active bans.
func (bm *BanManager) Clear() {
	_ = bm.ReleaseAll()
}
