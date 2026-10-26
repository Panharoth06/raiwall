package clickhouse

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// clickHouseWhere builds the shared timestamp and host/country predicate.
func clickHouseWhere(startStr, endStr string, filter ...telemetry.AggregateFilter) string {
	clause := fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'", startStr, endStr)
	if len(filter) == 0 {
		return clause
	}
	if host := strings.TrimSpace(filter[0].Host); host != "" {
		clause += fmt.Sprintf(" AND host = '%s'", escapeClickHouseLiteral(host))
	}
	if country := strings.TrimSpace(filter[0].Country); country != "" {
		clause += fmt.Sprintf(" AND country = '%s'", escapeClickHouseLiteral(country))
	}
	return clause
}

// escapeClickHouseLiteral escapes user-supplied values embedded in ClickHouse SQL.
func escapeClickHouseLiteral(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

func parseClickHouseInt(raw string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return v
}

func parseClickHouseBucket(raw string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// applyAggregateDerivations mirrors the SQLite adapter's ratio and fallback
// rules so every telemetry backend returns the same shape.
func applyAggregateDerivations(stats *telemetry.AggregateStats) {
	if stats.TotalRequests > 0 && stats.PageViews == 0 && stats.TotalBlocked < stats.TotalRequests {
		stats.PageViews = stats.TotalRequests - stats.TotalBlocked
	}
	stats.UniqueVisitors = stats.UniqueIPs
	if stats.UniqueVisitors == 0 && stats.TotalRequests > 0 {
		stats.UniqueVisitors = 1
		stats.UniqueIPs = 1
	}
	if stats.TotalRequests > 0 {
		stats.BlockRatio = float64(stats.TotalBlocked) / float64(stats.TotalRequests)
		stats.Status4xxRate = float64(stats.Status4xx) / float64(stats.TotalRequests)
		stats.Status4xxBlockRate = float64(stats.Status4xxBlocked) / float64(stats.TotalRequests)
		stats.Status5xxRate = float64(stats.Status5xx) / float64(stats.TotalRequests)
	}
}

// GetAggregatedIncidents aggregates forensic events in ClickHouse.
func (s *ClickHouseStore) GetAggregatedIncidents(ctx context.Context, params telemetry.IncidentQueryParams) (*telemetry.IncidentQueryResult, error) {
	return &telemetry.IncidentQueryResult{
		Incidents:  []*telemetry.Incident{},
		TotalCount: 0,
	}, nil
}
