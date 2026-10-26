package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// QueryAggregates computes summary metrics and top distributions in ClickHouse.
func (s *ClickHouseStore) QueryAggregates(ctx context.Context, start, end time.Time, filter ...telemetry.AggregateFilter) (*telemetry.AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startStr := start.UTC().Format("2006-01-02 15:04:05.000")
	endStr := end.UTC().Format("2006-01-02 15:04:05.000")

	stats := &telemetry.AggregateStats{
		TimeBuckets:   make([]telemetry.TimeBucketCount, 0),
		TopCountries:  make([]telemetry.TopCount, 0),
		TopRules:      make([]telemetry.TopCount, 0),
		TopIPs:        make([]telemetry.TopCount, 0),
		TopCategories: make([]telemetry.TopCount, 0),
	}

	whereClause := clickHouseWhere(startStr, endStr, filter...)

	totalSQL := fmt.Sprintf(`
		SELECT count() as total,
		       countIf(action IN ('block', 'ban')) as blocked,
		       countIf((method = 'GET' OR method = '') AND (status_code < 400 OR status_code = 0) AND action NOT IN ('block', 'ban')) as page_views,
		       uniqExactIf(client_ip, client_ip != '') as unique_ips,
		       uniqExactIf(client_ip, action IN ('block', 'ban') AND client_ip != '') as blocked_ips,
		       countIf((status_code >= 400 AND status_code < 500) OR action IN ('block', 'ban')) as status_4xx,
		       countIf(action IN ('block', 'ban') OR status_code = 403) as status_4xx_blocked,
		       countIf(status_code >= 500) as status_5xx
		FROM %s.%s
		WHERE %s
		FORMAT JSON
	`, s.database, s.table, whereClause)

	resp, err := s.execWithRetry(ctx, totalSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Total            string `json:"total"`
				Blocked          string `json:"blocked"`
				PageViews        string `json:"page_views"`
				UniqueIPs        string `json:"unique_ips"`
				BlockedIPs       string `json:"blocked_ips"`
				Status4xx        string `json:"status_4xx"`
				Status4xxBlocked string `json:"status_4xx_blocked"`
				Status5xx        string `json:"status_5xx"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil && len(d.Data) > 0 {
			row := d.Data[0]
			stats.TotalRequests = parseClickHouseInt(row.Total)
			stats.TotalBlocked = parseClickHouseInt(row.Blocked)
			stats.PageViews = parseClickHouseInt(row.PageViews)
			stats.UniqueIPs = parseClickHouseInt(row.UniqueIPs)
			stats.BlockedIPs = parseClickHouseInt(row.BlockedIPs)
			stats.Status4xx = parseClickHouseInt(row.Status4xx)
			stats.Status4xxBlocked = parseClickHouseInt(row.Status4xxBlocked)
			stats.Status5xx = parseClickHouseInt(row.Status5xx)
		}
	}

	applyAggregateDerivations(stats)

	// Live QPS is always measured over the last 10 seconds, independent of the
	// selected reporting window, but keeps the host/country filter.
	qpsStartStr := time.Now().Add(-10 * time.Second).UTC().Format("2006-01-02 15:04:05.000")
	qpsEndStr := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	qpsSQL := fmt.Sprintf(`
		SELECT count() as recent
		FROM %s.%s
		WHERE %s
		FORMAT JSON
	`, s.database, s.table, clickHouseWhere(qpsStartStr, qpsEndStr, filter...))
	if resp, err := s.execWithRetry(ctx, qpsSQL, nil); err == nil {
		var d struct {
			Data []struct {
				Recent string `json:"recent"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil && len(d.Data) > 0 {
			stats.QPS = float64(parseClickHouseInt(d.Data[0].Recent)) / 10.0
		}
	}

	countrySQL := fmt.Sprintf(`
		SELECT country, count() as cnt
		FROM %s.%s
		WHERE %s AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, whereClause)
	if resp, err := s.execWithRetry(ctx, countrySQL, nil); err == nil {
		var d struct {
			Data []struct {
				Country string `json:"country"`
				Cnt     string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				stats.TopCountries = append(stats.TopCountries, telemetry.TopCount{Key: r.Country, Count: parseClickHouseInt(r.Cnt)})
			}
		}
	}

	ruleSQL := fmt.Sprintf(`
		SELECT rule_id, count() as cnt
		FROM %s.%s
		WHERE %s AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, whereClause)
	if resp, err := s.execWithRetry(ctx, ruleSQL, nil); err == nil {
		var d struct {
			Data []struct {
				RuleID string `json:"rule_id"`
				Cnt    string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				stats.TopRules = append(stats.TopRules, telemetry.TopCount{Key: r.RuleID, Count: parseClickHouseInt(r.Cnt)})
			}
		}
	}

	ipSQL := fmt.Sprintf(`
		SELECT client_ip, count() as cnt
		FROM %s.%s
		WHERE %s AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, whereClause)
	if resp, err := s.execWithRetry(ctx, ipSQL, nil); err == nil {
		var d struct {
			Data []struct {
				ClientIP string `json:"client_ip"`
				Cnt      string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				stats.TopIPs = append(stats.TopIPs, telemetry.TopCount{Key: r.ClientIP, Count: parseClickHouseInt(r.Cnt)})
			}
		}
	}

	categorySQL := fmt.Sprintf(`
		SELECT attack_category, count() as cnt
		FROM %s.%s
		WHERE %s AND attack_category != ''
		GROUP BY attack_category
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, whereClause)
	if resp, err := s.execWithRetry(ctx, categorySQL, nil); err == nil {
		var d struct {
			Data []struct {
				Category string `json:"attack_category"`
				Cnt      string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				stats.TopCategories = append(stats.TopCategories, telemetry.TopCount{Key: r.Category, Count: parseClickHouseInt(r.Cnt)})
			}
		}
	}

	// Match the SQLite bucket granularity so dashboards render consistently
	// regardless of which telemetry backend is active.
	bucketExpr := "toStartOfHour"
	duration := end.Sub(start)
	if duration <= 2*time.Hour {
		bucketExpr = "toStartOfMinute"
	} else if duration > 48*time.Hour {
		bucketExpr = "toStartOfDay"
	}

	bucketSQL := fmt.Sprintf(`
		SELECT toString(%s(timestamp)) as bucket,
		       count() as total,
		       countIf(action IN ('block', 'ban')) as blocked
		FROM %s.%s
		WHERE %s
		GROUP BY bucket
		ORDER BY bucket ASC
		FORMAT JSON
	`, bucketExpr, s.database, s.table, whereClause)
	if resp, err := s.execWithRetry(ctx, bucketSQL, nil); err == nil {
		var d struct {
			Data []struct {
				Bucket  string `json:"bucket"`
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				stats.TimeBuckets = append(stats.TimeBuckets, telemetry.TimeBucketCount{
					Bucket: parseClickHouseBucket(r.Bucket),
					Total:  parseClickHouseInt(r.Total),
					Block:  parseClickHouseInt(r.Blocked),
				})
			}
		}
	}

	return stats, nil
}
