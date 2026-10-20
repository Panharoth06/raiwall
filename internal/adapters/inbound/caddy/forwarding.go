package caddy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

// UpstreamRegistry manages cached UpstreamPool instances to avoid memory leaks.
type UpstreamRegistry struct {
	mu        sync.RWMutex
	pools     map[string]*UpstreamPool
	transport http.RoundTripper
}

// NewUpstreamRegistry initializes a new UpstreamRegistry.
func NewUpstreamRegistry() *UpstreamRegistry {
	return &UpstreamRegistry{
		pools: make(map[string]*UpstreamPool),
		transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
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
	r.pools[key] = pool
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
	for _, p := range r.pools {
		p.Stop()
	}
	r.pools = make(map[string]*UpstreamPool)
	if tr, ok := r.transport.(*http.Transport); ok && tr != nil {
		tr.CloseIdleConnections()
	}
}

// ProxyToBackend forwards an HTTP request to an upstream dial address using the given transport.
func ProxyToBackend(w http.ResponseWriter, r *http.Request, dial string, transport http.RoundTripper) error {
	scheme := "http"
	dialHost := dial
	if strings.HasPrefix(dialHost, "https://") {
		scheme = "https"
		dialHost = strings.TrimPrefix(dialHost, "https://")
	} else if strings.HasPrefix(dialHost, "http://") {
		dialHost = strings.TrimPrefix(dialHost, "http://")
	}

	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = dialHost

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create upstream request: "+err.Error(), http.StatusBadGateway)
		return err
	}

	outReq.Header = r.Header.Clone()
	if r.Host != "" {
		outReq.Host = r.Host
	}

	if transport == nil {
		transport = http.DefaultTransport
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Upstream connection failed: "+err.Error(), http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}
