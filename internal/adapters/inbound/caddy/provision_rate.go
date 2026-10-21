package caddy

import (
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/redis"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/caddyserver/caddy/v2"
)

func (m *Middleware) provisionRate(_ caddy.Context) error {
	if m.banManager == nil {
		m.banManager = rate.NewBanManager(m.logger)
	}
	if m.trapCtrl == nil {
		m.trapCtrl = bot.NewTrapController(&banStoreAdapter{bm: m.banManager}, bot.DefaultBanDuration, m.logger)
	}

	if m.rateStorage == nil {
		if m.RateLimitConfig != nil && strings.ToLower(m.RateLimitConfig.StorageType) == "redis" && m.RateLimitConfig.StorageAddr != "" {
			redisClient := redis.NewSimpleRESPClient(m.RateLimitConfig.StorageAddr, 2*time.Second)
			m.rateStorage = redis.NewRedisStorage(redis.RedisStorageConfig{
				Client:            redisClient,
				FallbackOnFailure: true,
			})
			m.banManager.SetBanStorage(redis.NewRedisBanStorage(redisClient, "rw:bans:"))
		} else {
			m.rateStorage = rate.NewMemoryStorage()
		}
	}
	m.banManager.SetRateStorage(m.rateStorage)
	rateStorage := m.rateStorage

	if m.tier1Limiter == nil && m.RateLimitConfig != nil && m.RateLimitConfig.Tier1Rate > 0 {
		period := time.Duration(m.RateLimitConfig.Tier1Period)
		if period <= 0 {
			period = 10 * time.Second
		}
		burst := m.RateLimitConfig.Tier1Burst
		if burst < 0 {
			burst = 20
		}
		m.tier1Limiter = rate.NewTier1VelocityLimiter(rate.Tier1Config{
			Rate:             m.RateLimitConfig.Tier1Rate,
			Period:           period,
			Burst:            burst,
			Storage:          rateStorage,
			RouteClassifier:  m.routeClass,
			PoWEngine:        m.powEngine,
			ClearanceManager: m.clearanceMgr,
		})
	}

	if m.tier2Limiter == nil && m.RateLimitConfig != nil && m.RateLimitConfig.Tier2Threshold > 0 {
		window := time.Duration(m.RateLimitConfig.Tier2Window)
		if window <= 0 {
			window = 60 * time.Second
		}
		banDur := time.Duration(m.RateLimitConfig.Tier2BanDuration)
		if banDur <= 0 {
			banDur = 24 * time.Hour
		}
		m.tier2Limiter = rate.NewTier2AttackLimiter(rate.Tier2Config{
			Threshold:   m.RateLimitConfig.Tier2Threshold,
			Window:      window,
			BanDuration: banDur,
			BanManager:  m.banManager,
			Storage:     rateStorage,
			Logger:      m.logger,
		})
	}

	if m.tier3Trap == nil && m.RateLimitConfig != nil && m.RateLimitConfig.Tier3Threshold > 0 {
		window := time.Duration(m.RateLimitConfig.Tier3Window)
		if window <= 0 {
			window = 30 * time.Second
		}
		banDur := time.Duration(m.RateLimitConfig.Tier3BanDuration)
		if banDur <= 0 {
			banDur = 24 * time.Hour
		}
		m.tier3Trap = rate.NewTier3ScannerTrap(rate.Tier3Config{
			Threshold:   m.RateLimitConfig.Tier3Threshold,
			Window:      window,
			BanDuration: banDur,
			BanManager:  m.banManager,
			Storage:     rateStorage,
			Logger:      m.logger,
		})
	}

	if m.waitingRoom == nil && m.WaitingRoomConfig != nil && (m.WaitingRoomConfig.Enabled || m.WaitingRoomConfig.MaxConcurrentInFlight > 0) {
		ttl := time.Duration(m.WaitingRoomConfig.AdmissionTokenTTL)
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		m.waitingRoom = rate.NewWaitingRoomManager(rate.WaitingRoomConfig{
			MaxConcurrentInFlight: m.WaitingRoomConfig.MaxConcurrentInFlight,
			MaxQueueDepth:         m.WaitingRoomConfig.MaxQueueDepth,
			AdmissionRate:         m.WaitingRoomConfig.AdmissionRate,
			AdmissionTokenTTL:     ttl,
			TargetPaths:           m.WaitingRoomConfig.TargetPaths,
			Secret:                m.PoWSecret,
			Logger:                m.logger,
		})
	}

	return nil
}
