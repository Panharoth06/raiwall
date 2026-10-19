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

// AggregateStats provides summary analytics across a time window.
type AggregateStats struct {
	TotalRequests int64             `json:"total_requests"`
	TotalBlocked  int64             `json:"total_blocked"`
	BlockRatio    float64           `json:"block_ratio"`
	TimeBuckets   []TimeBucketCount `json:"time_buckets"`
	TopCountries  []TopCount        `json:"top_countries"`
	TopRules      []TopCount        `json:"top_rules"`
	TopIPs        []TopCount        `json:"top_ips"`
}

// ForensicStore is the pluggable storage interface for recording and querying security logs.
type ForensicStore interface {
	// SaveBatch writes a collection of forensic events in a single transaction or batch.
	SaveBatch(ctx context.Context, events []*ForensicEvent) error

	// Query returns matching forensic events according to criteria.
	Query(ctx context.Context, params QueryParams) (*QueryResult, error)

	// QueryAggregates computes high-level threat metrics, top entities, and time buckets.
	QueryAggregates(ctx context.Context, start, end time.Time) (*AggregateStats, error)

	// Prune deletes records older than maxAge.
	Prune(ctx context.Context, maxAge time.Duration) (int64, error)

	// Close cleans up connections and background workers.
	Close() error
}
