package caddy

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// UpstreamBackend represents a single monitored backend destination.
type UpstreamBackend struct {
	Dial                string
	Weight              int
	MaxFails            int
	FailTimeout         time.Duration
	HealthCheckPath     string
	HealthCheckInterval time.Duration
	ExpectedStatus      int
	Transport           http.RoundTripper

	healthy       atomic.Bool
	fails         atomic.Int32
	client        *http.Client
	stopChan      chan struct{}
	closeOnce     sync.Once
	currentWeight int
}

// IsHealthy returns whether this backend is currently considered healthy.
func (ub *UpstreamBackend) IsHealthy() bool {
	return ub.healthy.Load()
}

// UpstreamPool manages load balancing and health checks for a set of backends.
type UpstreamPool struct {
	mu       sync.RWMutex
	backends []*UpstreamBackend
	counter  atomic.Uint64
}

// NewUpstreamPool creates a pool of monitored upstream backends.
func NewUpstreamPool(targets []control.UpstreamTarget) *UpstreamPool {
	pool := &UpstreamPool{
		backends: make([]*UpstreamBackend, 0, len(targets)),
	}

	for _, t := range targets {
		weight := t.Weight
		if weight <= 0 {
			weight = 1
		}
		maxFails := t.MaxFails
		if maxFails <= 0 {
			maxFails = 2
		}
		interval := t.HealthCheckInterval
		if interval <= 0 {
			interval = 5 * time.Second
		}
		hcPath := t.HealthCheckPath
		if hcPath == "" {
			hcPath = "/healthz"
		}

		backend := &UpstreamBackend{
			Dial:                t.Dial,
			Weight:              weight,
			MaxFails:            maxFails,
			FailTimeout:         t.FailTimeout,
			HealthCheckPath:     hcPath,
			HealthCheckInterval: interval,
			ExpectedStatus:      http.StatusOK,
			stopChan:            make(chan struct{}),
			client: &http.Client{
				Timeout: 2 * time.Second,
			},
		}
		backend.healthy.Store(true) // assume healthy initially

		pool.backends = append(pool.backends, backend)
	}

	return pool
}

// Backends returns the list of backend instances in the pool.
func (p *UpstreamPool) Backends() []*UpstreamBackend {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]*UpstreamBackend, len(p.backends))
	copy(res, p.backends)
	return res
}

// StartHealthChecks begins background health check probes for all backends in the pool.
func (p *UpstreamPool) StartHealthChecks(ctx context.Context) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, b := range p.backends {
		if b.Transport != nil {
			b.client.Transport = b.Transport
		}
		go b.runHealthChecks(ctx)
	}
}

// Stop terminates all health check goroutines.
func (p *UpstreamPool) Stop() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, b := range p.backends {
		b.closeOnce.Do(func() {
			close(b.stopChan)
		})
	}
}

func (ub *UpstreamBackend) runHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(ub.HealthCheckInterval)
	defer ticker.Stop()

	// Initial immediate probe on startup
	ub.probe(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ub.stopChan:
			return
		case <-ticker.C:
			ub.probe(ctx)
		}
	}
}

func (ub *UpstreamBackend) probe(ctx context.Context) {
	url := fmt.Sprintf("http://%s%s", ub.Dial, ub.HealthCheckPath)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		ub.recordFailure()
		return
	}

	resp, err := ub.client.Do(req)
	if err != nil {
		ub.recordFailure()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == ub.ExpectedStatus {
		ub.recordSuccess()
	} else {
		ub.recordFailure()
	}
}

func (ub *UpstreamBackend) recordSuccess() {
	ub.fails.Store(0)
	ub.healthy.Store(true)
}

func (ub *UpstreamBackend) recordFailure() {
	fails := ub.fails.Add(1)
	if int(fails) >= ub.MaxFails {
		ub.healthy.Store(false)
	}
}

// NextBackend selects the next healthy backend using smooth weighted round-robin distribution.
func (p *UpstreamPool) NextBackend() (*UpstreamBackend, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.backends) == 0 {
		return nil, fmt.Errorf("no upstream backends configured")
	}

	healthy := make([]*UpstreamBackend, 0, len(p.backends))
	totalWeight := 0
	for _, b := range p.backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
			totalWeight += b.Weight
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("all upstream backends are unhealthy")
	}

	if len(healthy) == 1 {
		return healthy[0], nil
	}

	var best *UpstreamBackend
	for _, b := range healthy {
		b.currentWeight += b.Weight
		if best == nil || b.currentWeight > best.currentWeight {
			best = b
		}
	}

	best.currentWeight -= totalWeight
	return best, nil
}

// HealthyBackends returns a snapshot of currently healthy backends.
func (p *UpstreamPool) HealthyBackends() []*UpstreamBackend {
	p.mu.RLock()
	defer p.mu.RUnlock()

	res := make([]*UpstreamBackend, 0, len(p.backends))
	for _, b := range p.backends {
		if b.IsHealthy() {
			res = append(res, b)
		}
	}
	return res
}
