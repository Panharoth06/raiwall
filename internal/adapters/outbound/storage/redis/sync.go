package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
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
	active := control.GetActiveSnapshot()
	if active != nil {
		s.lastApplied = active.Version
	}
	s.mu.Unlock()

	_ = s.SyncLatest(s.ctx)

	msgCh, err := s.client.Subscribe(s.ctx, s.channel)
	if err != nil {
		return fmt.Errorf("failed to subscribe to cluster channel %q: %w", s.channel, err)
	}

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

	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		return fmt.Errorf("failed to fetch snapshot from redis: %w", err)
	}

	if notif.Hash != "" {
		h := sha256.Sum256([]byte(rawSnap))
		actualHash := hex.EncodeToString(h[:])
		if actualHash != notif.Hash {
			return fmt.Errorf("snapshot hash mismatch: expected %s, got %s", notif.Hash, actualHash)
		}
	}

	var snap control.ConfigSnapshot
	if err := json.Unmarshal([]byte(rawSnap), &snap); err != nil {
		return fmt.Errorf("failed to parse snapshot data: %w", err)
	}

	snap.RebuildIndex()

	if err := control.ValidateSnapshot(&snap); err != nil {
		return fmt.Errorf("pre-flight validation failed on cluster snapshot: %w", err)
	}

	control.StoreSnapshot(&snap)

	s.mu.Lock()
	s.lastApplied = snap.Version
	s.mu.Unlock()

	return nil
}

// SyncLatest polls Redis for the latest snapshot and applies it if newer than the local snapshot.
func (s *Subscriber) SyncLatest(ctx context.Context) error {
	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		return nil
	}

	var snap control.ConfigSnapshot
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
	if err := control.ValidateSnapshot(&snap); err != nil {
		return err
	}

	control.StoreSnapshot(&snap)

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
