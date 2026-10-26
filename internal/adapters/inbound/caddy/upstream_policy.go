package caddy

import (
	"fmt"
	"hash/fnv"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// SelectBackend picks a healthy backend according to the configured policy and
// returns a release function that must be called once the request completes.
func (p *UpstreamPool) SelectBackend(policy, clientIP string) (*UpstreamBackend, func(), error) {
	switch policy {
	case control.LoadBalancePrimaryBackup:
		b, err := p.firstHealthy()
		return b, func() {}, err
	case control.LoadBalanceIPHash:
		b, err := p.hashBackend(clientIP)
		return b, func() {}, err
	case control.LoadBalanceLeastConn:
		b, err := p.leastConnections()
		if err != nil {
			return nil, func() {}, err
		}
		b.inflight.Add(1)
		return b, func() { b.inflight.Add(-1) }, nil
	default:
		b, err := p.NextBackend()
		return b, func() {}, err
	}
}

func (p *UpstreamPool) firstHealthy() (*UpstreamBackend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.backends) == 0 {
		return nil, fmt.Errorf("no upstream backends configured")
	}
	for _, b := range p.backends {
		if b.IsHealthy() {
			return b, nil
		}
	}
	return nil, fmt.Errorf("all upstream backends are unhealthy")
}

func (p *UpstreamPool) hashBackend(clientIP string) (*UpstreamBackend, error) {
	healthy := p.HealthyBackends()
	if len(healthy) == 0 {
		return nil, fmt.Errorf("all upstream backends are unhealthy")
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientIP))
	return healthy[int(h.Sum32()%uint32(len(healthy)))], nil
}

func (p *UpstreamPool) leastConnections() (*UpstreamBackend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var best *UpstreamBackend
	var bestLoad int64
	for _, b := range p.backends {
		if !b.IsHealthy() {
			continue
		}
		load := b.inflight.Load()
		if best == nil || load < bestLoad {
			best, bestLoad = b, load
		}
	}
	if best == nil {
		return nil, fmt.Errorf("all upstream backends are unhealthy")
	}
	return best, nil
}
