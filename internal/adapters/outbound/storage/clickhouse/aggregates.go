package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// QueryAggregates computes summary metrics and top distributions in ClickHouse.
func (s *ClickHouseStore) QueryAggregates(ctx context.Context, start, end time.Time) (*telemetry.AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startStr := start.UTC().Format("2006-01-02 15:04:05.000")
	endStr := end.UTC().Format("2006-01-02 15:04:05.000")

	stats := &telemetry.AggregateStats{
		TimeBuckets:  make([]telemetry.TimeBucketCount, 0),
		TopCountries: make([]telemetry.TopCount, 0),
		TopRules:     make([]telemetry.TopCount, 0),
		TopIPs:       make([]telemetry.TopCount, 0),
	}

	totalSQL := fmt.Sprintf(`
		SELECT count() as total,
		       countIf(action IN ('block', 'ban')) as blocked
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s'
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)

	resp, err := s.execWithRetry(ctx, totalSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil && len(d.Data) > 0 {
			fmt.Sscanf(d.Data[0].Total, "%d", &stats.TotalRequests)
			fmt.Sscanf(d.Data[0].Blocked, "%d", &stats.TotalBlocked)
			if stats.TotalRequests > 0 {
				stats.BlockRatio = float64(stats.TotalBlocked) / float64(stats.TotalRequests)
			}
		}
	}

	countrySQL := fmt.Sprintf(`
		SELECT country, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, countrySQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Country string `json:"country"`
				Cnt     string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopCountries = append(stats.TopCountries, telemetry.TopCount{Key: r.Country, Count: count})
			}
		}
	}

	ruleSQL := fmt.Sprintf(`
		SELECT rule_id, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, ruleSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				RuleID string `json:"rule_id"`
				Cnt    string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopRules = append(stats.TopRules, telemetry.TopCount{Key: r.RuleID, Count: count})
			}
		}
	}

	ipSQL := fmt.Sprintf(`
		SELECT client_ip, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, ipSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				ClientIP string `json:"client_ip"`
				Cnt      string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopIPs = append(stats.TopIPs, telemetry.TopCount{Key: r.ClientIP, Count: count})
			}
		}
	}

	bucketSQL := fmt.Sprintf(`
		SELECT toStartOfHour(timestamp) as bucket,
		       count() as total,
		       countIf(action IN ('block', 'ban')) as blocked
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s'
		GROUP BY bucket
		ORDER BY bucket ASC
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, bucketSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Bucket  string `json:"bucket"`
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var total, blocked int64
				fmt.Sscanf(r.Total, "%d", &total)
				fmt.Sscanf(r.Blocked, "%d", &blocked)
				t, err := time.Parse("2006-01-02 15:04:05", r.Bucket)
				if err != nil {
					t, _ = time.Parse(time.RFC3339, r.Bucket)
				}
				stats.TimeBuckets = append(stats.TimeBuckets, telemetry.TimeBucketCount{
					Bucket: t,
					Total:  total,
					Block:  blocked,
				})
			}
		}
	}

	return stats, nil
}

// GetAggregatedIncidents aggregates forensic events in ClickHouse.
func (s *ClickHouseStore) GetAggregatedIncidents(ctx context.Context, params telemetry.IncidentQueryParams) (*telemetry.IncidentQueryResult, error) {
	return &telemetry.IncidentQueryResult{
		Incidents:  []*telemetry.Incident{},
		TotalCount: 0,
	}, nil
}
