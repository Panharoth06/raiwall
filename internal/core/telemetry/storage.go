package telemetry

import (
	"context"
	"time"
)

// QueryParams defines criteria for querying historical forensic logs.
type QueryParams struct {
	StartTime   time.Time `json:"start_time,omitempty"`
	EndTime     time.Time `json:"end_time,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	Action      string    `json:"action,omitempty"`
	RuleID      string    `json:"rule_id,omitempty"`
	Country     string    `json:"country,omitempty"`
	MinSeverity string    `json:"min_severity,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
}

// QueryResult encapsulates a page of forensic events with total match count.
type QueryResult struct {
	Events []*ForensicEvent `json:"events"`
	Total  int64            `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
}

// TopCount maps an identifier or category key to its aggregate count.
type TopCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// TimeBucketCount tracks total and blocked event counts in a time interval.
type TimeBucketCount struct {
	Bucket time.Time `json:"bucket"`
	Total  int64     `json:"total"`
	Block  int64     `json:"block"`
}

// AggregateFilter defines criteria for filtering summary metrics and top aggregations.
type AggregateFilter struct {
	Host    string `json:"host,omitempty"`
	Country string `json:"country,omitempty"`
}

// AggregateStats provides summary analytics across a time window.
type AggregateStats struct {
	TotalRequests      int64             `json:"total_requests"`
	TotalBlocked       int64             `json:"total_blocked"`
	BlockRatio         float64           `json:"block_ratio"`
	PageViews          int64             `json:"page_views"`
	UniqueVisitors     int64             `json:"unique_visitors"`
	UniqueIPs          int64             `json:"unique_ips"`
	BlockedIPs         int64             `json:"blocked_ips"`
	Status4xx          int64             `json:"status_4xx"`
	Status4xxRate      float64           `json:"status_4xx_rate"`
	Status4xxBlocked   int64             `json:"status_4xx_blocked"`
	Status4xxBlockRate float64           `json:"status_4xx_blocked_rate"`
	Status5xx          int64             `json:"status_5xx"`
	Status5xxRate      float64           `json:"status_5xx_rate"`
	QPS                float64           `json:"qps"`
	TimeBuckets        []TimeBucketCount `json:"time_buckets"`
	TopCountries       []TopCount        `json:"top_countries"`
	TopRules           []TopCount        `json:"top_rules"`
	TopIPs             []TopCount        `json:"top_ips"`
	TopCategories      []TopCount        `json:"top_categories"`
}

// Incident aggregates multiple forensic events occurring within a sliding 5-minute time window for a client IP and target host.
type Incident struct {
	ID           string         `json:"id"`
	ClientIP     string         `json:"client_ip"`
	Host         string         `json:"host"`
	StartTime    time.Time      `json:"start_time"`
	EndTime      time.Time      `json:"end_time"`
	TotalEvents  int64          `json:"total_events"`
	TotalBlocked int64          `json:"total_blocked"`
	Category     string         `json:"category"`
	MaxSeverity  string         `json:"max_severity"`
	TopRuleID    string         `json:"top_rule_id"`
	Country      string         `json:"country,omitempty"`
	SampleEvent  *ForensicEvent `json:"sample_event,omitempty"`
}

// IncidentQueryParams filters aggregated incidents.
type IncidentQueryParams struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	ClientIP  string    `json:"client_ip"`
	Host      string    `json:"host"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
}

// IncidentQueryResult contains paginated incident records.
type IncidentQueryResult struct {
	Incidents  []*Incident `json:"incidents"`
	TotalCount int64       `json:"total_count"`
}

// ForensicStore is the pluggable storage interface for recording and querying security logs.
type ForensicStore interface {
	// SaveBatch writes a collection of forensic events in a single transaction or batch.
	SaveBatch(ctx context.Context, events []*ForensicEvent) error

	// Query returns matching forensic events according to criteria.
	Query(ctx context.Context, params QueryParams) (*QueryResult, error)

	// QueryAggregates computes high-level threat metrics, top entities, and time buckets.
	QueryAggregates(ctx context.Context, start, end time.Time, filter ...AggregateFilter) (*AggregateStats, error)

	// GetAggregatedIncidents aggregates forensic events into 5-minute incident clusters.
	GetAggregatedIncidents(ctx context.Context, params IncidentQueryParams) (*IncidentQueryResult, error)

	// GetEventByID retrieves a single forensic event by its unique UUID.
	GetEventByID(ctx context.Context, eventID string) (*ForensicEvent, error)

	// Prune deletes records older than maxAge.
	Prune(ctx context.Context, maxAge time.Duration) (int64, error)

	// Close cleans up connections and background workers.
	Close() error
}
