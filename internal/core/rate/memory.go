package rate

import (
	"context"
	"sync"
	"time"
)

const numMemoryShards = 256

// memoryShard represents a single partitioned partition of rate limit state.
type memoryShard struct {
	mu      sync.RWMutex
	entries map[string]int64 // key -> TAT (UnixNano)
	exp     map[string]int64 // key -> expiration (UnixNano)
}

func newMemoryShard() *memoryShard {
	return &memoryShard{
		entries: make(map[string]int64),
		exp:     make(map[string]int64),
	}
}

// MemoryStorage provides an in-memory, thread-safe, partitioned GCRA RateStorage.
type MemoryStorage struct {
	shards []*memoryShard
	stopCh chan struct{}
	once   sync.Once
}

// NewMemoryStorage creates and initializes a MemoryStorage with an active background eviction worker.
func NewMemoryStorage() *MemoryStorage {
	s := &MemoryStorage{
		shards: make([]*memoryShard, numMemoryShards),
		stopCh: make(chan struct{}),
	}
	for i := 0; i < numMemoryShards; i++ {
		s.shards[i] = newMemoryShard()
	}

	go s.evictionLoop()

	return s
}

// NewMemoryLimiter creates a GCRALimiter backed by MemoryStorage.
func NewMemoryLimiter(cfg RateLimitConfig) *GCRALimiter {
	return NewGCRALimiter(NewMemoryStorage(), cfg)
}

// hashKey calculates an FNV-1a 32-bit hash for shard distribution.
func hashKey(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h
}

func (s *MemoryStorage) getShard(key string) *memoryShard {
	idx := hashKey(key) % numMemoryShards
	return s.shards[idx]
}

// EvalGCRA performs atomic GCRA evaluation and state update.
func (s *MemoryStorage) EvalGCRA(ctx context.Context, key string, cfg RateLimitConfig, cost int64, now time.Time) (*RateResult, error) {
	shard := s.getShard(key)
	nowNano := now.UnixNano()

	shard.mu.Lock()
	tatNano, exists := shard.entries[key]
	if exists {
		if exp, hasExp := shard.exp[key]; hasExp && nowNano > exp {
			delete(shard.entries, key)
			delete(shard.exp, key)
			exists = false
			tatNano = 0
		}
	}

	newTAT, res := CalculateGCRA(now, tatNano, exists, cfg, cost)
	if res.Allowed {
		shard.entries[key] = newTAT
		// Expire when the key has rested long enough to return to empty state (+ 1 second buffer)
		tNano := int64(cfg.Period / time.Duration(cfg.Rate))
		if tNano <= 0 {
			tNano = 1
		}
		tauNano := cfg.Burst * tNano
		shard.exp[key] = newTAT + tauNano + tNano + int64(time.Second)
	}
	shard.mu.Unlock()

	return res, nil
}

// Reset clears the rate limit state for key.
func (s *MemoryStorage) Reset(ctx context.Context, key string) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	delete(shard.entries, key)
	delete(shard.exp, key)
	shard.mu.Unlock()
	return nil
}

// Close stops the background eviction loop.
func (s *MemoryStorage) Close() error {
	s.once.Do(func() {
		close(s.stopCh)
	})
	return nil
}

// evictionLoop runs periodic eviction across shards.
func (s *MemoryStorage) evictionLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.EvictExpired()
		}
	}
}

// EvictExpired sweeps all shards and removes expired keys.
func (s *MemoryStorage) EvictExpired() int {
	nowNano := time.Now().UnixNano()
	evicted := 0

	for _, shard := range s.shards {
		shard.mu.Lock()
		for key, exp := range shard.exp {
			if nowNano > exp {
				delete(shard.entries, key)
				delete(shard.exp, key)
				evicted++
			}
		}
		shard.mu.Unlock()
	}

	return evicted
}

// Count returns the total number of active tracked keys across all shards.
func (s *MemoryStorage) Count() int {
	total := 0
	for _, shard := range s.shards {
		shard.mu.RLock()
		total += len(shard.entries)
		shard.mu.RUnlock()
	}
	return total
}
