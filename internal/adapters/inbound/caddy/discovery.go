package caddy

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	numericRegex = regexp.MustCompile(`^\d+$`)
	uuidRegex    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexHashRegex = regexp.MustCompile(`^[0-9a-fA-F]{16,64}$`)
)

// NormalizePathTemplate collapses dynamic parameters (numeric IDs, UUIDs, hex hashes)
// in URI paths into generic template variables (e.g. /users/123 -> /users/{id}).
func NormalizePathTemplate(path string) string {
	if path == "" || path == "/" {
		return "/"
	}

	// Strip query string if present
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	trailingSlash := strings.HasSuffix(path, "/") && path != "/"
	segments := strings.Split(strings.Trim(path, "/"), "/")
	normalized := make([]string, len(segments))

	for i, seg := range segments {
		cleanSeg := strings.TrimSpace(seg)
		if numericRegex.MatchString(cleanSeg) {
			normalized[i] = "{id}"
		} else if uuidRegex.MatchString(cleanSeg) {
			normalized[i] = "{id}"
		} else if hexHashRegex.MatchString(cleanSeg) {
			normalized[i] = "{hash}"
		} else {
			normalized[i] = cleanSeg
		}
	}

	res := "/" + strings.Join(normalized, "/")
	if trailingSlash && res != "/" {
		res += "/"
	}
	return res
}

// DiscoveredEndpoint holds aggregate metrics for a single API resource.
type DiscoveredEndpoint struct {
	AppID       string
	Method      string
	PathPattern string
	ContentType string
	HitCount    int64
	LastSeen    time.Time
}

// APIDiscoveryCataloger performs non-blocking, aggregated cataloging of clean API endpoints.
type APIDiscoveryCataloger struct {
	store       control.ControlStore
	logger      *zap.Logger
	inCh        chan DiscoveredEndpoint
	flushCh     chan chan struct{}
	stopCh      chan struct{}
	closeOnce   sync.Once
	flushTicker *time.Ticker

	mu         sync.Mutex
	aggregates map[string]*DiscoveredEndpoint
}

// NewAPIDiscoveryCataloger starts a background worker that flushes endpoint metrics periodically.
func NewAPIDiscoveryCataloger(store control.ControlStore, logger *zap.Logger, flushInterval time.Duration) *APIDiscoveryCataloger {
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	c := &APIDiscoveryCataloger{
		store:       store,
		logger:      logger,
		inCh:        make(chan DiscoveredEndpoint, 5000),
		flushCh:     make(chan chan struct{}),
		stopCh:      make(chan struct{}),
		flushTicker: time.NewTicker(flushInterval),
		aggregates:  make(map[string]*DiscoveredEndpoint),
	}

	go c.run()
	return c
}

// RecordRequest queues an API observation without blocking the HTTP request goroutine.
func (c *APIDiscoveryCataloger) RecordRequest(appID, method, rawPath, contentType string) {
	if c == nil || appID == "" {
		return
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	pattern := NormalizePathTemplate(rawPath)

	ct := strings.TrimSpace(contentType)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}

	select {
	case c.inCh <- DiscoveredEndpoint{
		AppID:       appID,
		Method:      method,
		PathPattern: pattern,
		ContentType: ct,
		HitCount:    1,
		LastSeen:    time.Now().UTC(),
	}:
	default:
		// Queue full: drop sampling to avoid adding latency to proxy data path
	}
}

func (c *APIDiscoveryCataloger) run() {
	for {
		select {
		case <-c.stopCh:
			c.flushTicker.Stop()
			c.drainAndFlush(context.Background())
			return
		case req := <-c.inCh:
			c.aggregate(req)
		case <-c.flushTicker.C:
			c.drainAndFlush(context.Background())
		case done := <-c.flushCh:
			c.drainAndFlush(context.Background())
			close(done)
		}
	}
}

func (c *APIDiscoveryCataloger) aggregate(req DiscoveredEndpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := req.AppID + "|" + req.Method + "|" + req.PathPattern
	if existing, ok := c.aggregates[key]; ok {
		existing.HitCount += req.HitCount
		if req.ContentType != "" {
			existing.ContentType = req.ContentType
		}
		if req.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = req.LastSeen
		}
	} else {
		c.aggregates[key] = &DiscoveredEndpoint{
			AppID:       req.AppID,
			Method:      req.Method,
			PathPattern: req.PathPattern,
			ContentType: req.ContentType,
			HitCount:    req.HitCount,
			LastSeen:    req.LastSeen,
		}
	}
}

func (c *APIDiscoveryCataloger) drainAndFlush(ctx context.Context) {
	for {
		select {
		case req := <-c.inCh:
			c.aggregate(req)
		default:
			c.persistSnapshot(ctx)
			return
		}
	}
}

func (c *APIDiscoveryCataloger) persistSnapshot(ctx context.Context) {
	c.mu.Lock()
	if len(c.aggregates) == 0 {
		c.mu.Unlock()
		return
	}
	snapshot := c.aggregates
	c.aggregates = make(map[string]*DiscoveredEndpoint)
	c.mu.Unlock()

	for _, ep := range snapshot {
		err := c.store.UpsertAPIResource(ctx, control.ApiResourceRecord{
			ID:          "res-" + uuid.New().String()[:8],
			AppID:       ep.AppID,
			Method:      ep.Method,
			PathPattern: ep.PathPattern,
			ContentType: ep.ContentType,
			HitCount:    ep.HitCount,
			LastSeen:    ep.LastSeen,
			CreatedAt:   ep.LastSeen,
		})
		if err != nil && c.logger != nil {
			c.logger.Warn("Failed to persist discovered API resource",
				zap.String("app_id", ep.AppID),
				zap.String("pattern", ep.PathPattern),
				zap.Error(err),
			)
		}
	}
}

// Flush persists all currently aggregated endpoints to the database.
func (c *APIDiscoveryCataloger) Flush(ctx context.Context) {
	if c == nil || c.store == nil {
		return
	}

	done := make(chan struct{})
	select {
	case c.flushCh <- done:
		select {
		case <-done:
		case <-ctx.Done():
		case <-c.stopCh:
		}
	case <-c.stopCh:
	}
}

// Close stops the cataloger and flushes remaining records.
func (c *APIDiscoveryCataloger) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
	return nil
}
