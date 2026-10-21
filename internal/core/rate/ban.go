package rate

import (
	"context"
	"fmt"
	"net"
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
	banStorage   BanStorage
	onBan        func(entry *BanEntry)
	onUnblock    func(target string)
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
	return bm.BanWithSite(ip, ja4, ttl, reason, "")
}

// BanWithSite registers an auto-ban for composite ClientIP + JA4 with optional siteID.
func (bm *BanManager) BanWithSite(ip net.IP, ja4 string, ttl time.Duration, reason string, siteID string) *BanEntry {
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
		SiteID:           siteID,
		Duration:         ttl,
		RemainingSeconds: int64(ttl.Seconds()),
		BannedAt:         now,
		ExpiresAt:        now.Add(ttl),
	}

	bm.mu.Lock()
	bm.entries[key] = entry
	bs := bm.banStorage
	onBan := bm.onBan
	bm.mu.Unlock()

	if bs != nil {
		_ = bs.StoreBan(context.Background(), entry)
	}
	if onBan != nil {
		onBan(entry)
	}

	if bm.logger != nil {
		bm.logger.Warn("Client auto-banned",
			zap.String("key", key),
			zap.String("client_ip", ipStr),
			zap.String("ja4", ja4),
			zap.String("reason", reason),
			zap.String("site_id", siteID),
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
