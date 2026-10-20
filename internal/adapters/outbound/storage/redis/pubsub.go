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

const (
	DefaultClusterChannel = "raiwall:cluster:events"
	DefaultSnapshotKey    = "raiwall:config:snapshot:latest"
	DefaultSnapshotTTL    = 7 * 24 * time.Hour
)

// VersionNotification is broadcast over Redis Pub/Sub when a new config revision is applied.
type VersionNotification struct {
	Version   uint64    `json:"version"`
	Hash      string    `json:"hash"`
	Author    string    `json:"author,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ClusterRedisClient defines the Redis operations required by the cluster synchronizer.
type ClusterRedisClient interface {
	Publish(ctx context.Context, channel string, message string) error
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Subscribe(ctx context.Context, channel string) (<-chan string, error)
	Ping(ctx context.Context) error
	Close() error
}

// Publisher publishes snapshot updates to the Redis cluster.
type Publisher struct {
	client      ClusterRedisClient
	channel     string
	snapshotKey string
	snapshotTTL time.Duration
}

// NewPublisher constructs a new cluster config Publisher.
func NewPublisher(client ClusterRedisClient) *Publisher {
	return &Publisher{
		client:      client,
		channel:     DefaultClusterChannel,
		snapshotKey: DefaultSnapshotKey,
		snapshotTTL: DefaultSnapshotTTL,
	}
}

// PublishSnapshot caches the snapshot in Redis and broadcasts the version notification.
func (p *Publisher) PublishSnapshot(ctx context.Context, snap *control.ConfigSnapshot, author string) error {
	if snap == nil {
		return errors.New("cannot publish nil snapshot")
	}

	snapData, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot for cluster: %w", err)
	}

	h := sha256.Sum256(snapData)
	hashStr := hex.EncodeToString(h[:])

	if err := p.client.Set(ctx, p.snapshotKey, string(snapData), p.snapshotTTL); err != nil {
		return fmt.Errorf("failed to cache snapshot in redis: %w", err)
	}

	notif := VersionNotification{
		Version:   snap.Version,
		Hash:      hashStr,
		Author:    author,
		Timestamp: time.Now().UTC(),
	}
	notifData, _ := json.Marshal(notif)

	if err := p.client.Publish(ctx, p.channel, string(notifData)); err != nil {
		return fmt.Errorf("failed to broadcast version notification: %w", err)
	}

	return nil
}

// PublishVersion is a helper satisfying ClusterPublisher.
func (p *Publisher) PublishVersion(ctx context.Context, version uint64) error {
	active := control.GetActiveSnapshot()
	if active == nil || active.Version != version {
		return nil
	}
	return p.PublishSnapshot(ctx, active, "cluster-master")
}

// MockRedisClient is a thread-safe, in-memory implementation of ClusterRedisClient for testing.
type MockRedisClient struct {
	mu          sync.RWMutex
	data        map[string]string
	subscribers map[string][]chan string
	failPing    bool
}

// NewMockRedisClient initializes an in-memory Redis mock.
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data:        make(map[string]string),
		subscribers: make(map[string][]chan string),
	}
}

func (m *MockRedisClient) Publish(ctx context.Context, channel string, message string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if chs, ok := m.subscribers[channel]; ok {
		for _, ch := range chs {
			select {
			case ch <- message:
			default:
			}
		}
	}
	return nil
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[key]
	if !ok {
		return "", errors.New("redis: nil")
	}
	return val, nil
}

func (m *MockRedisClient) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan string, 16)
	m.subscribers[channel] = append(m.subscribers[channel], ch)
	return ch, nil
}

func (m *MockRedisClient) Ping(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.failPing {
		return errors.New("redis connection refused")
	}
	return nil
}

func (m *MockRedisClient) SetFailPing(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failPing = fail
}

func (m *MockRedisClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, chs := range m.subscribers {
		for _, ch := range chs {
			close(ch)
		}
	}
	m.subscribers = make(map[string][]chan string)
	return nil
}
