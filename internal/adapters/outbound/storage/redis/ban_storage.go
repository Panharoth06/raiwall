package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/rate"
)

const (
	storeBanScript = `
local entryKey = KEYS[1]
local setKey = KEYS[2]
local data = ARGV[1]
local ttl = tonumber(ARGV[2])
local identifier = ARGV[3]
if ttl <= 0 then ttl = 86400 end
redis.call('SET', entryKey, data, 'EX', ttl)
redis.call('SADD', setKey, identifier)
return 1
`

	removeBanScript = `
local setKey = KEYS[1]
local prefix = ARGV[1]
local target = ARGV[2]
redis.call('DEL', prefix .. target)
redis.call('SREM', setKey, target)
local members = redis.call('SMEMBERS', setKey)
local prefixTarget = target .. '|'
local suffixTarget = '|' .. target
for _, m in ipairs(members) do
    if m == target or string.sub(m, 1, #prefixTarget) == prefixTarget or (#m >= #suffixTarget and string.sub(m, -#suffixTarget) == suffixTarget) then
        redis.call('DEL', prefix .. m)
        redis.call('SREM', setKey, m)
    end
end
return 1
`

	clearBansScript = `
local setKey = KEYS[1]
local prefix = ARGV[1]
local members = redis.call('SMEMBERS', setKey)
for _, m in ipairs(members) do
    redis.call('DEL', prefix .. m)
end
redis.call('DEL', setKey)
return #members
`

	listBansScript = `
local setKey = KEYS[1]
local prefix = ARGV[1]
local members = redis.call('SMEMBERS', setKey)
local result = {}
for _, m in ipairs(members) do
    local val = redis.call('GET', prefix .. m)
    if val then
        table.insert(result, val)
    else
        redis.call('SREM', setKey, m)
    end
end
return result
`
)

// RedisBanStorage implements rate.BanStorage over Redis with in-memory fallback.
type RedisBanStorage struct {
	client    RedisClient
	keyPrefix string
	mu        sync.RWMutex
	fallback  map[string]*rate.BanEntry
}

// NewRedisBanStorage creates a Redis-backed ban storage instance.
func NewRedisBanStorage(client RedisClient, keyPrefix string) *RedisBanStorage {
	if keyPrefix == "" {
		keyPrefix = "rw:bans:"
	}
	return &RedisBanStorage{
		client:    client,
		keyPrefix: keyPrefix,
		fallback:  make(map[string]*rate.BanEntry),
	}
}

func (s *RedisBanStorage) entryKey(key string) string {
	return s.keyPrefix + "entry:" + key
}

func (s *RedisBanStorage) setKey() string {
	return s.keyPrefix + "set"
}

// StoreBan writes the ban entry to Redis and fallback map.
func (s *RedisBanStorage) StoreBan(ctx context.Context, entry *rate.BanEntry) error {
	if entry == nil || entry.Key == "" {
		return nil
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal ban entry: %w", err)
	}

	ttlSec := int64(entry.Duration.Seconds())
	if ttlSec <= 0 {
		ttlSec = 86400
	}

	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	if client != nil {
		_, err := client.Eval(ctx, storeBanScript, []string{s.entryKey(entry.Key), s.setKey()}, string(data), ttlSec, entry.Key)
		if err == nil {
			return nil
		}
	}

	s.mu.Lock()
	s.fallback[entry.Key] = entry
	s.mu.Unlock()
	return nil
}

// RemoveBan deletes the ban entry from Redis and fallback map.
func (s *RedisBanStorage) RemoveBan(ctx context.Context, keyOrIP string) error {
	if keyOrIP == "" {
		return nil
	}

	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	if client != nil {
		_, _ = client.Eval(ctx, removeBanScript, []string{s.setKey()}, s.keyPrefix+"entry:", keyOrIP)
	}

	s.mu.Lock()
	delete(s.fallback, keyOrIP)
	for k, e := range s.fallback {
		if e.ClientIP == keyOrIP || e.Key == keyOrIP || e.JA4 == keyOrIP {
			delete(s.fallback, k)
		}
	}
	s.mu.Unlock()

	return nil
}

// ClearBans removes all bans from Redis and fallback map.
func (s *RedisBanStorage) ClearBans(ctx context.Context) error {
	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	if client != nil {
		_, _ = client.Eval(ctx, clearBansScript, []string{s.setKey()}, s.keyPrefix+"entry:")
	}

	s.mu.Lock()
	s.fallback = make(map[string]*rate.BanEntry)
	s.mu.Unlock()

	return nil
}

// ListBans retrieves all active ban entries from Redis, falling back to local memory if needed.
func (s *RedisBanStorage) ListBans(ctx context.Context) ([]*rate.BanEntry, error) {
	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	now := time.Now()
	if client != nil {
		res, err := client.Eval(ctx, listBansScript, []string{s.setKey()}, s.keyPrefix+"entry:")
		if err == nil {
			slice, ok := toInterfaceSlice(res)
			if ok {
				entries := make([]*rate.BanEntry, 0, len(slice))
				for _, item := range slice {
					str, ok := item.(string)
					if !ok {
						continue
					}
					var entry rate.BanEntry
					if err := json.Unmarshal([]byte(str), &entry); err == nil {
						if now.Before(entry.ExpiresAt) {
							entries = append(entries, &entry)
						}
					}
				}
				return entries, nil
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*rate.BanEntry, 0, len(s.fallback))
	for _, e := range s.fallback {
		if now.Before(e.ExpiresAt) {
			res = append(res, e)
		}
	}
	return res, nil
}
