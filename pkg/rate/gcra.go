package rate

import (
	"context"
	"time"
)

// GCRALimiter implements the RateLimiter interface backed by a pluggable RateStorage.
type GCRALimiter struct {
	storage RateStorage
	cfg     RateLimitConfig
}

// NewGCRALimiter creates a GCRALimiter with the given storage and configuration.
func NewGCRALimiter(storage RateStorage, cfg RateLimitConfig) *GCRALimiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 1
	}
	if cfg.Period <= 0 {
		cfg.Period = time.Second
	}
	if cfg.Burst < 0 {
		cfg.Burst = 0
	}
	return &GCRALimiter{
		storage: storage,
		cfg:     cfg,
	}
}

// Allow evaluates whether a request of the specified cost is permitted for key.
func (l *GCRALimiter) Allow(ctx context.Context, key string, cost int64) (*RateResult, error) {
	if cost <= 0 {
		cost = 1
	}
	return l.storage.EvalGCRA(ctx, key, l.cfg, cost, time.Now())
}

// Reset clears the rate limit state for key.
func (l *GCRALimiter) Reset(ctx context.Context, key string) error {
	return l.storage.Reset(ctx, key)
}

// Close closes the underlying storage.
func (l *GCRALimiter) Close() error {
	return l.storage.Close()
}

// Config returns the configured rate limit parameters.
func (l *GCRALimiter) Config() RateLimitConfig {
	return l.cfg
}

// CalculateGCRA executes the pure Generic Cell Rate Algorithm logic.
// It is pure and has zero allocations.
func CalculateGCRA(now time.Time, tatNano int64, hasTAT bool, cfg RateLimitConfig, cost int64) (int64, *RateResult) {
	if cost <= 0 {
		cost = 1
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 1
	}
	if cfg.Period <= 0 {
		cfg.Period = time.Second
	}
	if cfg.Burst < 0 {
		cfg.Burst = 0
	}

	tNano := int64(cfg.Period / time.Duration(cfg.Rate))
	if tNano <= 0 {
		tNano = 1
	}
	tauNano := cfg.Burst * tNano

	nowNano := now.UnixNano()
	if !hasTAT || tatNano < nowNano {
		tatNano = nowNano
	}

	increment := cost * tNano
	candidateTAT := tatNano + increment

	// Burst capacity ceiling: tau + tNano
	maxAllowedTAT := nowNano + tauNano + tNano

	if candidateTAT > maxAllowedTAT {
		// Non-conforming: request exceeds rate limit and burst tolerance
		retryAfterNano := candidateTAT - maxAllowedTAT
		resetAfterNano := tatNano - nowNano
		if resetAfterNano < 0 {
			resetAfterNano = 0
		}
		return tatNano, &RateResult{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: time.Duration(retryAfterNano),
			ResetAfter: time.Duration(resetAfterNano),
			Limit:      cfg.Rate,
			Burst:      cfg.Burst,
		}
	}

	// Conforming: request permitted
	resetAfterNano := candidateTAT - nowNano
	if resetAfterNano < 0 {
		resetAfterNano = 0
	}

	var remaining int64
	remainingDiff := maxAllowedTAT - candidateTAT
	if remainingDiff > 0 {
		remaining = remainingDiff / tNano
	}

	return candidateTAT, &RateResult{
		Allowed:    true,
		Remaining:  remaining,
		RetryAfter: 0,
		ResetAfter: time.Duration(resetAfterNano),
		Limit:      cfg.Rate,
		Burst:      cfg.Burst,
	}
}
