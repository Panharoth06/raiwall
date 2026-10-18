package rate

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
)

// DefaultTier2Threshold is the attack count threshold within Window (10 attacks).
const DefaultTier2Threshold int64 = 10

// DefaultTier2Window is the sliding window duration (60 seconds).
const DefaultTier2Window = 60 * time.Second

// DefaultTier2BanDuration is the auto-ban duration (24 hours).
const DefaultTier2BanDuration = 24 * time.Hour

// DefaultTier2IPThreshold is the pure-IP escalation attack threshold (30 attacks).
const DefaultTier2IPThreshold int64 = 30

// Tier2Config configures Tier2AttackLimiter.
type Tier2Config struct {
	Threshold          int64
	Window             time.Duration
	BanDuration        time.Duration
	BanManager         *BanManager
	Storage            RateStorage
	EnableIPEscalation bool
	IPThreshold        int64
	Logger             *zap.Logger
}

// Tier2AttackLimiter tracks security threat blocks and triggers auto-bans when frequency limits are breached.
type Tier2AttackLimiter struct {
	limiter            RateLimiter
	ipLimiter          RateLimiter
	banManager         *BanManager
	banDuration        time.Duration
	enableIPEscalation bool
	logger             *zap.Logger
}

// NewTier2AttackLimiter initializes a new Tier2AttackLimiter.
func NewTier2AttackLimiter(cfg Tier2Config) *Tier2AttackLimiter {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = DefaultTier2Threshold
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultTier2Window
	}
	banDur := cfg.BanDuration
	if banDur <= 0 {
		banDur = DefaultTier2BanDuration
	}

	storage := cfg.Storage
	if storage == nil {
		storage = NewMemoryStorage()
	}

	// Burst = 0 means capacity is 1 + Burst = 1, so Rate = threshold, Period = window
	// allows up to threshold requests within window.
	limiter := NewGCRALimiter(storage, RateLimitConfig{
		Rate:   threshold,
		Period: window,
		Burst:  threshold - 1,
	})

	banMgr := cfg.BanManager
	if banMgr == nil {
		banMgr = NewBanManager(cfg.Logger)
	}

	var ipLimiter RateLimiter
	if cfg.EnableIPEscalation {
		ipThresh := cfg.IPThreshold
		if ipThresh <= 0 {
			ipThresh = DefaultTier2IPThreshold
		}
		ipLimiter = NewGCRALimiter(storage, RateLimitConfig{
			Rate:   ipThresh,
			Period: window,
			Burst:  ipThresh - 1,
		})
	}

	return &Tier2AttackLimiter{
		limiter:            limiter,
		ipLimiter:          ipLimiter,
		banManager:         banMgr,
		banDuration:        banDur,
		enableIPEscalation: cfg.EnableIPEscalation,
		logger:             cfg.Logger,
	}
}

// RecordAttack records a threat block event and checks if the client should be auto-banned.
func (t2 *Tier2AttackLimiter) RecordAttack(ctx context.Context, ip net.IP, ja4 string, ruleID string, reason string) (bool, *BanEntry, error) {
	key := fmt.Sprintf("t2:%s", BanKey(ip, ja4))
	res, err := t2.limiter.Allow(ctx, key, 1)
	if err != nil {
		return false, nil, fmt.Errorf("tier2 rate limit error: %w", err)
	}

	if !res.Allowed {
		// Threshold exceeded: trigger composite ClientIP + JA4 auto-ban
		banReason := fmt.Sprintf("tier2_attack_frequency_exceeded: rule=%s reason=%s", ruleID, reason)
		entry := t2.banManager.Ban(ip, ja4, t2.banDuration, banReason)
		if t2.logger != nil {
			t2.logger.Warn("Tier 2 attack frequency exceeded, auto-banning client",
				zap.String("client_ip", entry.ClientIP),
				zap.String("ja4", entry.JA4),
				zap.String("rule_id", ruleID),
				zap.String("reason", reason),
				zap.Duration("ban_duration", t2.banDuration),
			)
		}
		return true, entry, nil
	}

	// Check optional pure-IP escalation if enabled
	if t2.enableIPEscalation && ip != nil && t2.ipLimiter != nil {
		ipKey := fmt.Sprintf("t2:ip:%s", ip.String())
		ipRes, ipErr := t2.ipLimiter.Allow(ctx, ipKey, 1)
		if ipErr == nil && !ipRes.Allowed {
			banReason := fmt.Sprintf("tier2_ip_escalation: multiple attacks from shared IP (%s)", reason)
			entry := t2.banManager.BanIP(ip, t2.banDuration, banReason)
			if t2.logger != nil {
				t2.logger.Warn("Tier 2 pure IP escalation auto-ban triggered",
					zap.String("client_ip", ip.String()),
					zap.String("reason", reason),
				)
			}
			return true, entry, nil
		}
	}

	return false, nil, nil
}

// BanManager returns the active BanManager.
func (t2 *Tier2AttackLimiter) BanManager() *BanManager {
	return t2.banManager
}

// Close releases allocated limiter resources.
func (t2 *Tier2AttackLimiter) Close() error {
	_ = t2.limiter.Close()
	if t2.ipLimiter != nil {
		_ = t2.ipLimiter.Close()
	}
	return t2.banManager.Close()
}
