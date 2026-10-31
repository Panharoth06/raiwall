package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

const (
	defaultSubscriberPollInterval = 10 * time.Second
	subscriberReconnectMin        = 100 * time.Millisecond
	subscriberReconnectMax        = 5 * time.Second
)

// SubscriberConfig holds configuration options for the worker node cluster synchronizer.
type SubscriberConfig struct {
	Client       ClusterRedisClient
	Channel      string
	SnapshotKey  string
	PollInterval time.Duration
	OnBan        func(entry *rate.BanEntry)
	OnUnblock    func(target string)
	OnUnblockAll func()
	// OnConnected runs after every successful (re)subscribe, so missed events
	// from a Redis gap can be reconciled from shared storage.
	OnConnected func()
}

// Subscriber runs on worker nodes to subscribe to version notifications and poll for drift.
type Subscriber struct {
	client       ClusterRedisClient
	channel      string
	snapshotKey  string
	pollInterval time.Duration
	onBan        func(entry *rate.BanEntry)
	onUnblock    func(target string)
	onUnblockAll func()
	onConnected  func()

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu           sync.RWMutex
	lastApplied  uint64
	lastRevision int64
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
		cfg.PollInterval = defaultSubscriberPollInterval
	}

	return &Subscriber{
		client:       cfg.Client,
		channel:      cfg.Channel,
		snapshotKey:  cfg.SnapshotKey,
		pollInterval: cfg.PollInterval,
		onBan:        cfg.OnBan,
		onUnblock:    cfg.OnUnblock,
		onUnblockAll: cfg.OnUnblockAll,
		onConnected:  cfg.OnConnected,
	}
}

// Start begins the Pub/Sub subscriber and the periodic drift poll. A Redis
// outage at startup is not fatal: the subscription is retried in the
// background while local state keeps serving traffic.
func (s *Subscriber) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	if active := control.GetActiveSnapshot(); active != nil {
		s.lastApplied = active.Version
	}
	s.mu.Unlock()

	_ = s.SyncLatest(s.ctx)

	s.wg.Add(1)
	go s.subscribeLoop()

	s.wg.Add(1)
	go s.pollLoop()

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

func (s *Subscriber) subscribeLoop() {
	defer s.wg.Done()

	backoff := subscriberReconnectMin
	for {
		messages, err := s.client.Subscribe(s.ctx, s.channel)
		if err != nil {
			if !s.waitForRetry(backoff) {
				return
			}
			backoff = min(backoff*2, subscriberReconnectMax)
			continue
		}
		backoff = subscriberReconnectMin
		if s.onConnected != nil {
			s.onConnected()
		}
		if !s.consume(messages) {
			return
		}
	}
}

// consume pumps messages until the channel closes (a retry is due) or the
// subscriber stops (false).
func (s *Subscriber) consume(messages <-chan string) bool {
	for {
		select {
		case <-s.ctx.Done():
			return false
		case raw, ok := <-messages:
			if !ok {
				return true
			}
			s.handleMessage(raw)
		}
	}
}

func (s *Subscriber) pollLoop() {
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
}

func (s *Subscriber) waitForRetry(delay time.Duration) bool {
	select {
	case <-s.ctx.Done():
		return false
	case <-time.After(delay):
		return true
	}
}

func (s *Subscriber) handleMessage(raw string) {
	var banMsg BanBroadcastMessage
	if err := json.Unmarshal([]byte(raw), &banMsg); err == nil && banMsg.Type != "" {
		switch banMsg.Type {
		case "unblock":
			if s.onUnblock != nil {
				s.onUnblock(banMsg.Target)
			}
		case "unblock_all":
			if s.onUnblockAll != nil {
				s.onUnblockAll()
			}
		case "ban":
			if s.onBan != nil && banMsg.Entry != nil {
				s.onBan(banMsg.Entry)
			}
		}
		return
	}

	var notif VersionNotification
	if err := json.Unmarshal([]byte(raw), &notif); err != nil {
		return
	}
	_ = s.handleNotification(s.ctx, &notif)
}

func (s *Subscriber) handleNotification(ctx context.Context, notif *VersionNotification) error {
	if notif == nil {
		return errors.New("nil notification")
	}

	// Redis delivers each message at most once per subscriber, but a
	// reconnecting peer can receive the same revision again. Config versions
	// cannot order events because rollbacks decrease them.
	s.mu.RLock()
	lastRevision := s.lastRevision
	s.mu.RUnlock()
	if notif.Revision != 0 && notif.Revision == lastRevision {
		return nil
	}

	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		return fmt.Errorf("failed to fetch snapshot from redis: %w", err)
	}

	snap, err := control.ApplyRemoteSnapshot(ctx, []byte(rawSnap), notif.Hash)
	if errors.Is(err, control.ErrSnapshotUnchanged) {
		s.setApplied(snapVersion(snap))
		s.setRevision(notif.Revision)
		return nil
	}
	if err != nil {
		return err
	}
	s.setApplied(snap.Version)
	s.setRevision(notif.Revision)
	return nil
}

// SyncLatest polls Redis for the latest snapshot and applies it if newer than the local snapshot.
func (s *Subscriber) SyncLatest(ctx context.Context) error {
	rawSnap, err := s.client.Get(ctx, s.snapshotKey)
	if err != nil {
		return nil
	}

	snap, err := control.ApplyRemoteSnapshot(ctx, []byte(rawSnap), "")
	if errors.Is(err, control.ErrSnapshotUnchanged) {
		s.setApplied(snapVersion(snap))
		return nil
	}
	if err != nil {
		return err
	}
	s.setApplied(snap.Version)
	return nil
}

// LastAppliedVersion returns the latest version applied by the subscriber.
func (s *Subscriber) LastAppliedVersion() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastApplied
}

// setApplied advances the applied marker; an older notification must not move
// it backwards after a newer version was already applied.
func (s *Subscriber) setApplied(version uint64) {
	s.mu.Lock()
	if version > s.lastApplied {
		s.lastApplied = version
	}
	s.mu.Unlock()
}

func (s *Subscriber) setRevision(revision int64) {
	if revision == 0 {
		return
	}
	s.mu.Lock()
	if revision > s.lastRevision {
		s.lastRevision = revision
	}
	s.mu.Unlock()
}

// snapVersion tolerates the nil snapshot an apply error may return.
func snapVersion(snap *control.ConfigSnapshot) uint64 {
	if snap == nil {
		return 0
	}
	return snap.Version
}
