package rate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
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

// RedisClient defines the client methods required by RedisStorage.
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
	Del(ctx context.Context, keys ...string) error
	Ping(ctx context.Context) error
	Close() error
}

// RedisStorageConfig configures RedisStorage.
type RedisStorageConfig struct {
	Client            RedisClient
	KeyPrefix         string
	FallbackOnFailure bool
	FallbackStorage   RateStorage
}

// RedisStorage implements RateStorage backed by Redis with local in-memory fallback.
type RedisStorage struct {
	client            RedisClient
	keyPrefix         string
	fallbackOnFailure bool
	fallback          RateStorage
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
		fallback = NewMemoryStorage()
	}

	return &RedisStorage{
		client:            cfg.Client,
		keyPrefix:         prefix,
		fallbackOnFailure: cfg.FallbackOnFailure,
		fallback:          fallback,
	}
}

// EvalGCRA evaluates or updates rate limit state for key via Redis Lua script.
// If Redis fails and FallbackOnFailure is enabled, it transparently falls back to local memory.
func (s *RedisStorage) EvalGCRA(ctx context.Context, key string, cfg RateLimitConfig, cost int64, now time.Time) (*RateResult, error) {
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

		// Redis error: evaluate fallback
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

// SetClient updates the active Redis client (e.g. after connection recovery).
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

func parseLuaResult(val any, cfg RateLimitConfig) (*RateResult, error) {
	slice, ok := toInterfaceSlice(val)
	if !ok || len(slice) < 4 {
		return nil, fmt.Errorf("invalid gcra lua response type: %T (%v)", val, val)
	}

	allowedInt := toInt64(slice[0])
	remaining := toInt64(slice[1])
	retryAfterMs := toInt64(slice[2])
	resetAfterMs := toInt64(slice[3])

	return &RateResult{
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

// SimpleRESPClient is a zero-dependency, pure-Go Redis client implementing RedisClient.
type SimpleRESPClient struct {
	addr    string
	timeout time.Duration
	dialer  func(network, addr string) (net.Conn, error)
	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
}

// NewSimpleRESPClient creates a SimpleRESPClient connected to addr.
func NewSimpleRESPClient(addr string, timeout time.Duration) *SimpleRESPClient {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &SimpleRESPClient{
		addr:    addr,
		timeout: timeout,
	}
}

// SetDialer allows overriding the network dialer (useful for testing or custom transports).
func (c *SimpleRESPClient) SetDialer(dialer func(network, addr string) (net.Conn, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialer = dialer
}

func (c *SimpleRESPClient) ensureConn() error {
	if c.conn != nil {
		return nil
	}
	var conn net.Conn
	var err error
	if c.dialer != nil {
		conn, err = c.dialer("tcp", c.addr)
	} else {
		conn, err = net.DialTimeout("tcp", c.addr, c.timeout)
	}
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

func (c *SimpleRESPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.reader = nil
		return err
	}
	return nil
}

func (c *SimpleRESPClient) Ping(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	if _, err := c.conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	resp, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	if s, ok := resp.(string); ok && strings.EqualFold(s, "PONG") {
		return nil
	}
	return nil
}

func (c *SimpleRESPClient) Del(ctx context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	cmd := buildRESPCommand(append([]string{"DEL"}, keys...)...)
	if _, err := c.conn.Write(cmd); err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	_, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *SimpleRESPClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return nil, err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	cmdParts := []string{"EVAL", script, strconv.Itoa(len(keys))}
	cmdParts = append(cmdParts, keys...)
	for _, a := range args {
		cmdParts = append(cmdParts, fmt.Sprintf("%v", a))
	}

	cmd := buildRESPCommand(cmdParts...)
	if _, err := c.conn.Write(cmd); err != nil {
		c.conn.Close()
		c.conn = nil
		return nil, err
	}
	resp, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return nil, err
	}
	return resp, nil
}

func buildRESPCommand(parts ...string) []byte {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		buf.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(p), p))
	}
	return []byte(buf.String())
}

func parseRESP(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("empty resp line")
	}

	prefix := line[0]
	content := line[1:]

	switch prefix {
	case '+': // Simple string
		return content, nil
	case '-': // Error
		return nil, errors.New(content)
	case ':': // Integer
		return strconv.ParseInt(content, 10, 64)
	case '$': // Bulk string
		length, err := strconv.Atoi(content)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:length]), nil
	case '*': // Array
		count, err := strconv.Atoi(content)
		if err != nil {
			return nil, err
		}
		if count == -1 {
			return nil, nil
		}
		items := make([]any, count)
		for i := 0; i < count; i++ {
			item, err := parseRESP(r)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unknown resp prefix: %c", prefix)
	}
}
