package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
)

// SubscriberConfig holds configuration options for the worker node cluster synchronizer.
type SubscriberConfig struct {
	Client       ClusterRedisClient
	Channel      string
	SnapshotKey  string
	PollInterval time.Duration
}

// Subscriber runs on worker nodes to subscribe to version notifications and poll for drift.
type Subscriber struct {
	client       ClusterRedisClient
	channel      string
	snapshotKey  string
	pollInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu          sync.RWMutex
	lastApplied uint64
}

// NewSubscriber creates a new cluster Subscriber.
func NewSubscriber(cfg SubscriberConfig) *Subscriber {
	if cfg.Channel == "" {
		cfg.Channel = DefaultClusterChannel
	}
	if cfg.SnapshotKey == "" {
		cfg.SnapshotKey = DefaultSnapshotKey
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}

	return &Subscriber{
		client:       cfg.Client,
		channel:      cfg.Channel,
		snapshotKey:  cfg.SnapshotKey,
		pollInterval: cfg.PollInterval,
	}
}

// Start begins the Pub/Sub subscriber and the periodic reconnect re-synchronization loop.
func (s *Subscriber) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	active := config.GetActiveSnapshot()
	if active != nil {
		s.lastApplied = active.Version
	}
	s.mu.Unlock()

	// Initial synchronization on startup
	_ = s.SyncLatest(s.ctx)

	// Subscribe to Redis Pub/Sub events
	msgCh, err := s.client.Subscribe(s.ctx, s.channel)
	if err != nil {
		return fmt.Errorf("failed to subscribe to cluster channel %q: %w", s.channel, err)
	}

	// 1. Pub/Sub notification worker
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.ctx.Done():
				return
			case rawMsg, ok := <-msgCh:
				if !ok {
					return
				}
				var notif VersionNotification
				if err := json.Unmarshal([]byte(rawMsg), &notif); err != nil {
					continue
				}
				_ = s.handleNotification(s.ctx, &notif)
			}
		}
	}()

	// 2. Periodic poll / reconnect re-synchronization worker
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				_ = s.SyncLatest(s.ctx)
			}
		}
	}()

	return nil
}

// Stop shuts down the cluster synchronization workers.
func (s *Subscriber) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// handleNotification fetches and validates the snapshot referenced in a Pub/Sub event.
func (s *Subscriber) handleNotification(ctx context.Context, notif *VersionNotification) error {
	if notif == nil {
		return errors.New("nil notification")
	}

	s.mu.RLock()
	last := s.lastApplied
	s.mu.RUnlock()

	if notif.Version <= last {
		return nil
	}

	// Fetch cached snapshot from Redis
	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		return fmt.Errorf("failed to fetch snapshot from redis: %w", err)
	}

	// Verify SHA-256 hash if provided
	if notif.Hash != "" {
		h := sha256.Sum256([]byte(rawSnap))
		actualHash := hex.EncodeToString(h[:])
		if actualHash != notif.Hash {
			return fmt.Errorf("snapshot hash mismatch: expected %s, got %s", notif.Hash, actualHash)
		}
	}

	var snap config.ConfigSnapshot
	if err := json.Unmarshal([]byte(rawSnap), &snap); err != nil {
		return fmt.Errorf("failed to parse snapshot data: %w", err)
	}

	snap.RebuildIndex()

	if err := config.ValidateSnapshot(&snap); err != nil {
		return fmt.Errorf("pre-flight validation failed on cluster snapshot: %w", err)
	}

	// Atomic lock-free swap
	config.StoreSnapshot(&snap)

	s.mu.Lock()
	s.lastApplied = snap.Version
	s.mu.Unlock()

	return nil
}

// SyncLatest polls Redis for the latest snapshot and applies it if newer than the local snapshot.
func (s *Subscriber) SyncLatest(ctx context.Context) error {
	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		// Graceful fallback: Redis temporarily unavailable, continue serving active snapshot
		return nil
	}

	var snap config.ConfigSnapshot
	if err := json.Unmarshal([]byte(rawSnap), &snap); err != nil {
		return err
	}

	s.mu.RLock()
	last := s.lastApplied
	s.mu.RUnlock()

	if snap.Version <= last {
		return nil
	}

	snap.RebuildIndex()
	if err := config.ValidateSnapshot(&snap); err != nil {
		return err
	}

	config.StoreSnapshot(&snap)

	s.mu.Lock()
	s.lastApplied = snap.Version
	s.mu.Unlock()

	return nil
}

// LastAppliedVersion returns the latest version applied by the subscriber.
func (s *Subscriber) LastAppliedVersion() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastApplied
}
