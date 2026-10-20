package rate

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BanManager provides a high-performance, thread-safe ban store evaluated on the fast-path.
type BanManager struct {
	mu           sync.RWMutex
	entries      map[string]*BanEntry
	stopCh       chan struct{}
	once         sync.Once
	logger       *zap.Logger
	storage      RateStorage
	onUnblockAll func()
}

// NewBanManager creates and initializes a BanManager with an active eviction loop.
func NewBanManager(logger *zap.Logger) *BanManager {
	bm := &BanManager{
		entries: make(map[string]*BanEntry),
		stopCh:  make(chan struct{}),
		logger:  logger,
	}

	go bm.evictionLoop()

	return bm
}

// Ban registers an auto-ban for composite ClientIP + JA4.
func (bm *BanManager) Ban(ip net.IP, ja4 string, ttl time.Duration, reason string) *BanEntry {
	if bm == nil {
		return nil
	}
	key := BanKey(ip, ja4)
	if key == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultBanDuration
	}

	now := time.Now()
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	entry := &BanEntry{
		Key:              key,
		ClientIP:         ipStr,
		JA4:              ja4,
		Reason:           reason,
		Duration:         ttl,
		RemainingSeconds: int64(ttl.Seconds()),
		BannedAt:         now,
		ExpiresAt:        now.Add(ttl),
	}

	bm.mu.Lock()
	bm.entries[key] = entry
	bm.mu.Unlock()

	if bm.logger != nil {
		bm.logger.Warn("Client auto-banned",
			zap.String("key", key),
			zap.String("client_ip", ipStr),
			zap.String("ja4", ja4),
			zap.String("reason", reason),
			zap.Duration("ttl", ttl),
		)
	}

	return entry
}

// BanIP registers a pure IP-level ban (escalation for all traffic from this IP).
func (bm *BanManager) BanIP(ip net.IP, ttl time.Duration, reason string) *BanEntry {
	if bm == nil || ip == nil {
		return nil
	}
	return bm.Ban(ip, "", ttl, reason)
}

// IsBanned performs a fast-path check (<500ns) to determine if the client is currently banned.
func (bm *BanManager) IsBanned(ip net.IP, ja4 string) (bool, *BanEntry) {
	if bm == nil {
		return false, nil
	}
	now := time.Now()
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// 1. Check composite IP + JA4 ban
	if ipStr != "" && ja4 != "" {
		compKey := fmt.Sprintf("%s|%s", ipStr, ja4)
		if entry, exists := bm.entries[compKey]; exists {
			if now.Before(entry.ExpiresAt) {
				return true, entry
			}
		}
	}

	// 2. Check pure IP ban
	if ipStr != "" {
		if entry, exists := bm.entries[ipStr]; exists {
			if now.Before(entry.ExpiresAt) {
				return true, entry
			}
		}
	}

	// 3. Check JA4-only ban
	if ja4 != "" {
		if entry, exists := bm.entries[ja4]; exists {
			if now.Before(entry.ExpiresAt) {
				return true, entry
			}
		}
	}

	return false, nil
}

// Unban removes a ban by key.
func (bm *BanManager) Unban(key string) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	delete(bm.entries, key)
	bm.mu.Unlock()
}

// UnbanIP removes an IP ban.
func (bm *BanManager) UnbanIP(ip net.IP) {
	if bm != nil && ip != nil {
		bm.Unban(ip.String())
	}
}

// Count returns the active ban count.
func (bm *BanManager) Count() int {
	if bm == nil {
		return 0
	}
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.entries)
}

// SetRateStorage configures the distributed storage layer for ban eviction.
func (bm *BanManager) SetRateStorage(st RateStorage) {
	if bm == nil {
		return
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.storage = st
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

// ListBans returns all currently active, non-expired bans with calculated remaining duration.
func (bm *BanManager) ListBans() []*BanEntry {
	if bm == nil {
		return nil
	}
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	now := time.Now()
	res := make([]*BanEntry, 0, len(bm.entries))
	for _, e := range bm.entries {
		if now.Before(e.ExpiresAt) {
			clone := *e
			clone.RemainingSeconds = int64(time.Until(e.ExpiresAt).Seconds())
			if clone.RemainingSeconds < 0 {
				clone.RemainingSeconds = 0
			}
			res = append(res, &clone)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].BannedAt.After(res[j].BannedAt)
	})
	return res
}

// Release removes an active ban by key or IP and evicts from underlying rate storage.
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
		if e.ClientIP == keyOrIP || e.Key == keyOrIP {
			delete(bm.entries, k)
			found = true
		}
	}
	st := bm.storage
	bm.mu.Unlock()

	if st != nil {
		_ = st.Reset(context.Background(), keyOrIP)
	}
	return found
}

// ReleaseAll purges the entire active ban registry and invokes the unblock broadcast callback.
func (bm *BanManager) ReleaseAll() int {
	if bm == nil {
		return 0
	}
	bm.mu.Lock()
	count := len(bm.entries)
	bm.entries = make(map[string]*BanEntry)
	cb := bm.onUnblockAll
	bm.mu.Unlock()

	if cb != nil {
		cb()
	}
	return count
}

// Clear removes all active bans.
func (bm *BanManager) Clear() {
	_ = bm.ReleaseAll()
}

// EvictExpired sweeps the ban store and purges expired entries.
func (bm *BanManager) EvictExpired() int {
	if bm == nil {
		return 0
	}
	now := time.Now()
	bm.mu.Lock()
	defer bm.mu.Unlock()

	evicted := 0
	for k, entry := range bm.entries {
		if now.After(entry.ExpiresAt) {
			delete(bm.entries, k)
			evicted++
		}
	}
	return evicted
}

// Close terminates the background eviction goroutine.
func (bm *BanManager) Close() error {
	bm.once.Do(func() {
		close(bm.stopCh)
	})
	return nil
}

func (bm *BanManager) evictionLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-bm.stopCh:
			return
		case <-ticker.C:
			bm.EvictExpired()
		}
	}
}
