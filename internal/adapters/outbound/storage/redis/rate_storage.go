package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/rate"
)

// GCRALuaScript is the atomic GCRA rate limiting script executed in Redis.
const GCRALuaScript = `
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local period_ms = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local now_ms = tonumber(ARGV[5])

local t_ms = period_ms / rate
if t_ms <= 0 then t_ms = 1 end
local tau_ms = burst * t_ms

local tat_ms = redis.call('GET', key)
if not tat_ms then
    tat_ms = now_ms
else
    tat_ms = tonumber(tat_ms)
    if tat_ms < now_ms then
        tat_ms = now_ms
    end
end

local increment = cost * t_ms
local candidate_tat = tat_ms + increment
local max_allowed_tat = now_ms + tau_ms + t_ms

if candidate_tat > max_allowed_tat then
    local retry_after_ms = candidate_tat - max_allowed_tat
    local reset_after_ms = math.max(0, tat_ms - now_ms)
    return {0, 0, math.ceil(retry_after_ms), math.ceil(reset_after_ms)}
end

local reset_after_ms = math.max(0, candidate_tat - now_ms)
local remaining_diff = max_allowed_tat - candidate_tat
local remaining = 0
if remaining_diff > 0 then
    remaining = math.floor(remaining_diff / t_ms)
end

local ttl_sec = math.ceil((reset_after_ms + tau_ms + t_ms) / 1000) + 2
redis.call('SET', key, candidate_tat, 'EX', ttl_sec)

return {1, remaining, 0, math.ceil(reset_after_ms)}
`

// RedisStorageConfig configures RedisStorage.
type RedisStorageConfig struct {
	Client            RedisClient
	KeyPrefix         string
	FallbackOnFailure bool
	FallbackStorage   rate.RateStorage
}

// RedisStorage implements rate.RateStorage backed by Redis with local in-memory fallback.
type RedisStorage struct {
	client            RedisClient
	keyPrefix         string
	fallbackOnFailure bool
	fallback          rate.RateStorage
	mu                sync.RWMutex
}

// NewRedisStorage creates a new RedisStorage instance.
func NewRedisStorage(cfg RedisStorageConfig) *RedisStorage {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "rw:rate:"
	}
	fallback := cfg.FallbackStorage
	if fallback == nil && cfg.FallbackOnFailure {
		fallback = rate.NewMemoryStorage()
	}

	return &RedisStorage{
		client:            cfg.Client,
		keyPrefix:         prefix,
		fallbackOnFailure: cfg.FallbackOnFailure,
		fallback:          fallback,
	}
}

// EvalGCRA evaluates or updates rate limit state for key via Redis Lua script.
func (s *RedisStorage) EvalGCRA(ctx context.Context, key string, cfg rate.RateLimitConfig, cost int64, now time.Time) (*rate.RateResult, error) {
	fullKey := s.keyPrefix + key
	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	if client != nil {
		periodMs := cfg.Period.Milliseconds()
		if periodMs <= 0 {
			periodMs = 1000
		}
		nowMs := now.UnixNano() / int64(time.Millisecond)

		resAny, err := client.Eval(ctx, GCRALuaScript, []string{fullKey}, cfg.Rate, periodMs, cfg.Burst, cost, nowMs)
		if err == nil {
			return parseLuaResult(resAny, cfg)
		}

		if !s.fallbackOnFailure || s.fallback == nil {
			return nil, fmt.Errorf("redis gcra error: %w", err)
		}
	}

	if s.fallback != nil {
		return s.fallback.EvalGCRA(ctx, key, cfg, cost, now)
	}

	return nil, errors.New("redis client not configured and no fallback storage available")
}

// Reset clears the rate limit state for key in Redis and fallback.
func (s *RedisStorage) Reset(ctx context.Context, key string) error {
	fullKey := s.keyPrefix + key
	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()

	var redisErr error
	if client != nil {
		redisErr = client.Del(ctx, fullKey)
	}
	if s.fallback != nil {
		_ = s.fallback.Reset(ctx, key)
	}
	return redisErr
}

// SetClient updates the active Redis client.
func (s *RedisStorage) SetClient(client RedisClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client = client
}

// Close releases client and fallback resources.
func (s *RedisStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.client != nil {
		err = s.client.Close()
	}
	if s.fallback != nil {
		_ = s.fallback.Close()
	}
	return err
}

func parseLuaResult(val any, cfg rate.RateLimitConfig) (*rate.RateResult, error) {
	slice, ok := toInterfaceSlice(val)
	if !ok || len(slice) < 4 {
		return nil, fmt.Errorf("invalid gcra lua response type: %T (%v)", val, val)
	}

	allowedInt := toInt64(slice[0])
	remaining := toInt64(slice[1])
	retryAfterMs := toInt64(slice[2])
	resetAfterMs := toInt64(slice[3])

	return &rate.RateResult{
		Allowed:    allowedInt == 1,
		Remaining:  remaining,
		RetryAfter: time.Duration(retryAfterMs) * time.Millisecond,
		ResetAfter: time.Duration(resetAfterMs) * time.Millisecond,
		Limit:      cfg.Rate,
		Burst:      cfg.Burst,
	}, nil
}

func toInterfaceSlice(val any) ([]any, bool) {
	switch v := val.(type) {
	case []any:
		return v, true
	case []int64:
		res := make([]any, len(v))
		for i, x := range v {
			res[i] = x
		}
		return res, true
	default:
		return nil, false
	}
}

func toInt64(val any) int64 {
	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}
