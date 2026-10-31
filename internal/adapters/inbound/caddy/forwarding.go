package caddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// MatchForwardingRule selects the active forwarding rule with the longest matching prefix for the given request path.
func MatchForwardingRule(rules []control.ForwardingRule, path string) *control.ForwardingRule {
	if len(rules) == 0 {
		return nil
	}

	normPath := path
	if normPath == "" {
		normPath = "/"
	}

	var bestMatch *control.ForwardingRule
	bestLen := -1

	for i := range rules {
		rule := &rules[i]
		if !rule.IsActive {
			continue
		}

		prefix := rule.Prefix
		if prefix == "" {
			prefix = "/"
		}

		matched := false
		if prefix == "/" {
			matched = true
		} else if strings.HasSuffix(prefix, "/") {
			matched = strings.HasPrefix(normPath, prefix) || normPath == strings.TrimSuffix(prefix, "/")
		} else {
			matched = normPath == prefix || strings.HasPrefix(normPath, prefix+"/")
		}

		if matched && len(prefix) > bestLen {
			bestMatch = rule
			bestLen = len(prefix)
		}
	}

	return bestMatch
}

// Upstream transport timeouts. Without these a stalled backend can pin a
// worker goroutine for the lifetime of the connection (TASKS.md 0.8).
const (
	upstreamDialTimeout           = 10 * time.Second
	upstreamResponseHeaderTimeout = 30 * time.Second
	upstreamIdleConnTimeout       = 90 * time.Second
	upstreamTLSHandshakeTimeout   = 10 * time.Second
)

// UpstreamRegistry manages cached UpstreamPool instances to avoid memory leaks.
type UpstreamRegistry struct {
	mu        sync.RWMutex
	pools     map[string]*UpstreamPool
	transport http.RoundTripper

	// ctx bounds the lifetime of every health-check goroutine the registry
	// starts, so Close tears them all down.
	ctx    context.Context
	cancel context.CancelFunc
}

// NewUpstreamRegistry initializes a new UpstreamRegistry.
func NewUpstreamRegistry() *UpstreamRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	return &UpstreamRegistry{
		pools: make(map[string]*UpstreamPool),
		transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   upstreamDialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       upstreamIdleConnTimeout,
			ResponseHeaderTimeout: upstreamResponseHeaderTimeout,
			TLSHandshakeTimeout:   upstreamTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetTransport overrides the HTTP round tripper (useful for testing or custom dialers).
func (r *UpstreamRegistry) SetTransport(rt http.RoundTripper) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transport = rt
}

// TargetsKey generates a deterministic cache key for a slice of UpstreamTargets.
func TargetsKey(targets []control.UpstreamTarget) string {
	data, _ := json.Marshal(targets)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}

// GetOrCreatePool retrieves or constructs an UpstreamPool for the given targets.
func (r *UpstreamRegistry) GetOrCreatePool(targets []control.UpstreamTarget) *UpstreamPool {
	key := TargetsKey(targets)
	r.mu.RLock()
	if pool, ok := r.pools[key]; ok {
		r.mu.RUnlock()
		return pool
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if pool, ok := r.pools[key]; ok {
		return pool
	}

	pool := NewUpstreamPool(targets)
	for _, b := range pool.backends {
		if b.Transport == nil {
			b.Transport = r.transport
		}
	}
	r.pools[key] = pool
	// Active health checks previously had no production caller, so unhealthy
	// backends were never detected (TASKS.md 0.8). StartHealthChecks is
	// idempotent per backend, so a cached pool never accumulates goroutines.
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	pool.StartHealthChecks(ctx)
	return pool
}

// SharedTransport returns the shared HTTP transport for upstream communication.
func (r *UpstreamRegistry) SharedTransport() http.RoundTripper {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.transport
}

// Close stops all health checks and frees resources.
func (r *UpstreamRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	for _, p := range r.pools {
		p.Stop()
	}
	r.pools = make(map[string]*UpstreamPool)
	if tr, ok := r.transport.(*http.Transport); ok && tr != nil {
		tr.CloseIdleConnections()
	}
}
