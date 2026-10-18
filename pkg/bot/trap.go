package bot

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DefaultBanDuration is the standard auto-ban duration (24 hours).
const DefaultBanDuration = 24 * time.Hour

// BanEntry records metadata about an auto-banned client.
type BanEntry struct {
	Key       string    `json:"key"`
	ClientIP  string    `json:"client_ip"`
	JA4       string    `json:"ja4,omitempty"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BanStore manages thread-safe storage and lookup of banned clients.
type BanStore interface {
	Ban(ip net.IP, ja4 string, ttl time.Duration, reason string)
	IsBanned(ip net.IP, ja4 string) (bool, *BanEntry)
	Unban(key string)
	EvictExpired() int
	Count() int
	Clear()
	Close()
}

// MemoryBanStore provides an in-memory, thread-safe implementation of BanStore.
type MemoryBanStore struct {
	mu      sync.RWMutex
	entries map[string]*BanEntry
	stopCh  chan struct{}
}

// NewMemoryBanStore creates an initialized MemoryBanStore with an active background eviction worker.
func NewMemoryBanStore() *MemoryBanStore {
	s := &MemoryBanStore{
		entries: make(map[string]*BanEntry),
		stopCh:  make(chan struct{}),
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.EvictExpired()
			}
		}
	}()

	return s
}

// ClientBanKey builds the composite lookup key from IP and JA4.
func ClientBanKey(ip net.IP, ja4 string) string {
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}
	if ipStr != "" && ja4 != "" {
		return fmt.Sprintf("%s|%s", ipStr, ja4)
	}
	if ipStr != "" {
		return ipStr
	}
	return ja4
}

// Ban registers a client key with expiration and reason.
func (s *MemoryBanStore) Ban(ip net.IP, ja4 string, ttl time.Duration, reason string) {
	key := ClientBanKey(ip, ja4)
	if key == "" {
		return
	}
	if ttl <= 0 {
		ttl = DefaultBanDuration
	}

	now := time.Now()
	entry := &BanEntry{
		Key:       key,
		ClientIP:  "",
		JA4:       ja4,
		Reason:    reason,
		BannedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	if ip != nil {
		entry.ClientIP = ip.String()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = entry
}

// IsBanned checks whether the client is currently banned by composite key or IP.
func (s *MemoryBanStore) IsBanned(ip net.IP, ja4 string) (bool, *BanEntry) {
	now := time.Now()

	s.mu.RLock()
	// 1. Check composite key ip|ja4
	compositeKey := ClientBanKey(ip, ja4)
	if entry, ok := s.entries[compositeKey]; ok {
		if now.Before(entry.ExpiresAt) {
			s.mu.RUnlock()
			return true, entry
		}
	}

	// 2. Fall back to IP alone
	if ip != nil {
		ipKey := ip.String()
		if entry, ok := s.entries[ipKey]; ok {
			if now.Before(entry.ExpiresAt) {
				s.mu.RUnlock()
				return true, entry
			}
		}
	}
	s.mu.RUnlock()

	return false, nil
}

// Unban removes a banned key.
func (s *MemoryBanStore) Unban(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// EvictExpired removes all expired ban entries from the store and returns the count.
func (s *MemoryBanStore) EvictExpired() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	evicted := 0
	for k, entry := range s.entries {
		if now.After(entry.ExpiresAt) {
			delete(s.entries, k)
			evicted++
		}
	}
	return evicted
}

// Count returns the number of active unexpired banned clients.
func (s *MemoryBanStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, entry := range s.entries {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// Clear flushes all entries.
func (s *MemoryBanStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*BanEntry)
}

// Close releases resources.
func (s *MemoryBanStore) Close() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

// TrapController orchestrates honeypot trap trips, auto-banning, and fast-path blocking.
type TrapController struct {
	store       BanStore
	banDuration time.Duration
	logger      *zap.Logger
}

// NewTrapController constructs an initialized TrapController.
func NewTrapController(store BanStore, banDuration time.Duration, logger *zap.Logger) *TrapController {
	if store == nil {
		store = NewMemoryBanStore()
	}
	if banDuration <= 0 {
		banDuration = DefaultBanDuration
	}
	return &TrapController{
		store:       store,
		banDuration: banDuration,
		logger:      logger,
	}
}

// Store returns the underlying BanStore.
func (tc *TrapController) Store() BanStore {
	return tc.store
}

// HandleTrap triggers an immediate auto-ban for a client that accessed a honeypot trap link.
func (tc *TrapController) HandleTrap(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) {
	reason := "HONEYPOT_TRAP: crawler accessed hidden honeypot link"
	tc.store.Ban(clientIP, ja4, tc.banDuration, reason)

	if tc.logger != nil {
		ipStr := ""
		if clientIP != nil {
			ipStr = clientIP.String()
		}
		tc.logger.Warn("Crawler fell into honeypot trap, client auto-banned",
			zap.String("client_ip", ipStr),
			zap.String("ja4", ja4),
			zap.String("path", r.URL.Path),
			zap.Duration("ban_duration", tc.banDuration),
		)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Client identified as malicious automated crawler and banned.</p></body></html>"))
}

// IsClientBanned checks if clientIP + ja4 is actively banned.
func (tc *TrapController) IsClientBanned(clientIP net.IP, ja4 string) (bool, *BanEntry) {
	return tc.store.IsBanned(clientIP, ja4)
}
