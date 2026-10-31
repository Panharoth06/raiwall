package caddy

import (
	"context"
	"fmt"
	"time"

	api "github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/redis"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

const (
	// clusterStatusPingTimeout keeps the admin status endpoint responsive when
	// Redis is down instead of blocking on the command timeout.
	clusterStatusPingTimeout = time.Second
	// banBroadcastQueueSize bounds pending ban broadcasts. A burst that
	// overflows it is dropped and recovered by the reconnect reconciliation;
	// the alternative is unbounded goroutines during a Redis outage.
	banBroadcastQueueSize = 1024
)

// provisionCluster wires the Redis-backed HA state: ban hydration, ban
// fan-out, config subscription, and live cluster status. Without a Redis
// client (standalone mode) it is a no-op.
func (m *Middleware) provisionCluster(_ caddy.Context) error {
	if m.redisClient == nil || m.banManager == nil {
		return nil
	}

	publisher := redis.NewPublisher(m.redisClient)
	publisher.SetChannel(m.clusterChannel())
	m.clusterPub = publisher
	m.startBanBroadcaster(publisher)

	// Pub/Sub does not replay messages, so both the initial boot and every
	// reconnect reconcile bans from shared storage.
	m.reconcileBans()

	subscriber := redis.NewSubscriber(redis.SubscriberConfig{
		Client:       m.redisClient,
		Channel:      m.clusterChannel(),
		OnBan:        m.banManager.ApplyRemoteBan,
		OnUnblock:    m.banManager.ApplyRemoteUnblock,
		OnUnblockAll: m.banManager.ApplyRemoteUnblockAll,
		OnConnected:  m.reconcileBans,
	})
	m.clusterSub = subscriber
	// The subscriber owns its reconnect loop, so a Redis outage during
	// provisioning does not fail startup or block local traffic.
	if err := subscriber.Start(context.Background()); err != nil {
		return fmt.Errorf("start cluster subscriber: %w", err)
	}

	if m.controlAPI != nil {
		m.controlAPI.SetClusterPublisher(publisher)
		m.controlAPI.SetClusterStatusProvider(clusterStatusProvider{middleware: m})
	}

	// A declarative deploy happened before the publisher existed; announce the
	// resulting state once so peers converge too.
	if m.declarativeDeployed {
		m.publishActiveSnapshot(publisher, "declarative")
	}

	if m.logger != nil {
		m.logger.Info("cluster state sync enabled",
			zap.String("channel", m.clusterChannel()),
			zap.Int("bans_after_reconcile", m.banManager.Count()),
		)
	}
	return nil
}

// reconcileBans mirrors the shared ban set into local memory after connecting.
func (m *Middleware) reconcileBans() {
	if m.banManager == nil {
		return
	}
	if err := m.banManager.Hydrate(context.Background()); err != nil && m.logger != nil {
		m.logger.Warn("failed to reconcile bans with cluster storage", zap.Error(err))
	}
}

func (m *Middleware) publishActiveSnapshot(publisher *redis.Publisher, author string) {
	snap := control.GetActiveSnapshot()
	if snap == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), redisCommandTimeout)
		defer cancel()
		if err := publisher.PublishSnapshot(ctx, snap, author); err != nil && m.logger != nil {
			m.logger.Warn("failed to publish snapshot to cluster", zap.Error(err))
		}
	}()
}

// startBanBroadcaster publishes bans from one worker through a bounded queue,
// keeping the request hot path off Redis and avoiding a goroutine per ban.
func (m *Middleware) startBanBroadcaster(publisher *redis.Publisher) {
	queue := make(chan *rate.BanEntry, banBroadcastQueueSize)
	stop := make(chan struct{})
	m.clusterBanQueue, m.clusterStop = queue, stop

	m.clusterWG.Add(1)
	go func() {
		defer m.clusterWG.Done()
		for {
			select {
			case <-stop:
				return
			case entry := <-queue:
				ctx, cancel := context.WithTimeout(context.Background(), redisCommandTimeout)
				err := publisher.PublishBan(ctx, entry)
				cancel()
				if err != nil && m.logger != nil {
					m.logger.Warn("failed to broadcast ban to cluster", zap.Error(err))
				}
			}
		}
	}()

	// Remote applies never reach this callback: they use ApplyRemoteBan, so
	// the event cannot loop around the cluster.
	m.banManager.SetOnBan(func(entry *rate.BanEntry) {
		select {
		case queue <- entry:
		default:
			if m.logger != nil {
				m.logger.Warn("cluster ban broadcast queue full; dropping event",
					zap.String("key", entry.Key))
			}
		}
	})
}

func (m *Middleware) clusterChannel() string {
	if m.RateLimitConfig != nil && m.RateLimitConfig.ClusterChannel != "" {
		return m.RateLimitConfig.ClusterChannel
	}
	return redis.DefaultClusterChannel
}

// clusterStatusProvider reports live HA state to the control-plane API.
type clusterStatusProvider struct {
	middleware *Middleware
}

// ClusterStatus implements api.ClusterStatusProvider.
func (p clusterStatusProvider) ClusterStatus(ctx context.Context) api.ClusterStatus {
	activeVersion := uint64(0)
	if snap := control.GetActiveSnapshot(); snap != nil {
		activeVersion = snap.Version
	}

	remote := control.RemoteAppliedStatus()
	appliedVersion := remote.AppliedVersion
	if appliedVersion == 0 {
		appliedVersion = activeVersion
	}

	pingCtx, cancel := context.WithTimeout(ctx, clusterStatusPingTimeout)
	defer cancel()
	connected := p.middleware.redisClient != nil && p.middleware.redisClient.Ping(pingCtx) == nil

	banCount := 0
	if p.middleware.banManager != nil {
		banCount = p.middleware.banManager.Count()
	}

	return api.ClusterStatus{
		Mode:           "redis",
		RedisConnected: connected,
		Channel:        p.middleware.clusterChannel(),
		ActiveVersion:  activeVersion,
		AppliedVersion: appliedVersion,
		AppliedHash:    remote.AppliedHash,
		LastApplyError: remote.LastApplyError,
		BanCount:       banCount,
	}
}
