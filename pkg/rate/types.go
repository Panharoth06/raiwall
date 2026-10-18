package rate

import (
	"context"
	"time"
)

// RateLimiter is the common interface for rate limiting implementations.
type RateLimiter interface {
	// Allow checks whether a request with the given cost should be allowed for key.
	Allow(ctx context.Context, key string, cost int64) (*RateResult, error)
	// Reset clears the rate limit state for the given key.
	Reset(ctx context.Context, key string) error
	// Close releases any resources held by the limiter.
	Close() error
}

// RateLimitConfig defines the rate limiting parameters.
type RateLimitConfig struct {
	Rate   int64         // Number of requests permitted per Period
	Period time.Duration // Time window for Rate
	Burst  int64         // Maximum burst capacity allowed beyond Rate
}

// RateResult represents the outcome of an Allow evaluation.
type RateResult struct {
	Allowed    bool          // Whether the request is permitted
	Remaining  int64         // Estimated remaining capacity within burst window
	RetryAfter time.Duration // Time to wait before retrying (0 if Allowed)
	ResetAfter time.Duration // Time until full capacity is restored
	Limit      int64         // Configured rate limit
	Burst      int64         // Configured burst tolerance
}

// RateStorage is the pluggable storage backend for GCRA rate limiting.
type RateStorage interface {
	// EvalGCRA evaluates or updates the rate limit state for key atomically.
	EvalGCRA(ctx context.Context, key string, cfg RateLimitConfig, cost int64, now time.Time) (*RateResult, error)
	// Reset clears rate limit state for key.
	Reset(ctx context.Context, key string) error
	// Close terminates storage connections or background routines.
	Close() error
}
