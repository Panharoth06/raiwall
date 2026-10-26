package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// QueryAggregates computes summary metrics and top aggregations across a time interval using PostgreSQL.
func (s *TelemetryStore) QueryAggregates(ctx context.Context, start, end time.Time, filter ...telemetry.AggregateFilter) (*telemetry.AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startUTC := start.UTC()
	endUTC := end.UTC()

	stats := &telemetry.AggregateStats{
		TimeBuckets:   make([]telemetry.TimeBucketCount, 0),
		TopCountries:  make([]telemetry.TopCount, 0),
		TopRules:      make([]telemetry.TopCount, 0),
		TopIPs:        make([]telemetry.TopCount, 0),
		TopCategories: make([]telemetry.TopCount, 0),
	}

	whereClause, args := aggregateWhere(startUTC, endUTC, filter...)

	totalQuery := fmt.Sprintf(`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN (method = 'GET' OR method = '') AND (status_code < 400 OR status_code = 0) AND action NOT IN ('block', 'ban') THEN 1 ELSE 0 END), 0),
		       COUNT(DISTINCT NULLIF(client_ip, '')),
		       COALESCE(COUNT(DISTINCT CASE WHEN action IN ('block', 'ban') THEN NULLIF(client_ip, '') END), 0),
		       COALESCE(SUM(CASE WHEN (status_code >= 400 AND status_code < 500) OR action IN ('block', 'ban') THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') OR status_code = 403 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), 0)
		FROM forensic_events
		WHERE %s
	`, whereClause)

	if err := s.db.QueryRowContext(ctx, totalQuery, args...).Scan(
		&stats.TotalRequests,
		&stats.TotalBlocked,
		&stats.PageViews,
		&stats.UniqueIPs,
		&stats.BlockedIPs,
		&stats.Status4xx,
		&stats.Status4xxBlocked,
		&stats.Status5xx,
	); err != nil {
		return nil, fmt.Errorf("query postgres totals: %w", err)
	}

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

	// Live QPS is always measured over the last 10 seconds, independent of the
	// selected reporting window, but keeps the host/country filter.
	qpsWhere, qpsArgs := aggregateWhere(time.Now().Add(-10*time.Second).UTC(), time.Now().UTC(), filter...)
	qpsQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM forensic_events
		WHERE %s
	`, qpsWhere)
	var recentCount int64
	if err := s.db.QueryRowContext(ctx, qpsQuery, qpsArgs...).Scan(&recentCount); err == nil {
		stats.QPS = float64(recentCount) / 10.0
	}

	countryQuery := fmt.Sprintf(`
		SELECT country, COUNT(*) as cnt
		FROM forensic_events
		WHERE %s AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
	`, whereClause)
	if cRows, err := s.db.QueryContext(ctx, countryQuery, args...); err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var tc telemetry.TopCount
			if err := cRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopCountries = append(stats.TopCountries, tc)
			}
		}
	}

	ruleQuery := fmt.Sprintf(`
		SELECT rule_id, COUNT(*) as cnt
		FROM forensic_events
		WHERE %s AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
	`, whereClause)
	if rRows, err := s.db.QueryContext(ctx, ruleQuery, args...); err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var tc telemetry.TopCount
			if err := rRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopRules = append(stats.TopRules, tc)
			}
		}
	}

	ipQuery := fmt.Sprintf(`
		SELECT client_ip, COUNT(*) as cnt
		FROM forensic_events
		WHERE %s AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
	`, whereClause)
	if ipRows, err := s.db.QueryContext(ctx, ipQuery, args...); err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var tc telemetry.TopCount
			if err := ipRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopIPs = append(stats.TopIPs, tc)
			}
		}
	}

	categoryQuery := fmt.Sprintf(`
		SELECT attack_category, COUNT(*) as cnt
		FROM forensic_events
		WHERE %s AND attack_category != ''
		GROUP BY attack_category
		ORDER BY cnt DESC
		LIMIT 10
	`, whereClause)
	if catRows, err := s.db.QueryContext(ctx, categoryQuery, args...); err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var tc telemetry.TopCount
			if err := catRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopCategories = append(stats.TopCategories, tc)
			}
		}
	}

	// Match the SQLite bucket granularity so dashboards render consistently
	// regardless of which telemetry backend is active.
	bucketExpr := "date_trunc('hour', timestamp AT TIME ZONE 'UTC')"
	bucketFormat := `YYYY-MM-DD"T"HH24:00:00"Z"`
	duration := end.Sub(start)
	if duration <= 2*time.Hour {
		bucketExpr = "date_trunc('minute', timestamp AT TIME ZONE 'UTC')"
		bucketFormat = `YYYY-MM-DD"T"HH24:MI:00"Z"`
	} else if duration > 48*time.Hour {
		bucketExpr = "date_trunc('day', timestamp AT TIME ZONE 'UTC')"
		bucketFormat = `YYYY-MM-DD"T00:00:00"Z"`
	}

	bucketQuery := fmt.Sprintf(`
		SELECT to_char(%s, '%s') as bucket,
		       COUNT(*) as total,
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0) as blocked
		FROM forensic_events
		WHERE %s
		GROUP BY 1
		ORDER BY 1 ASC
	`, bucketExpr, bucketFormat, whereClause)
	if bRows, err := s.db.QueryContext(ctx, bucketQuery, args...); err == nil {
		defer bRows.Close()
		for bRows.Next() {
			var (
				tbc       telemetry.TimeBucketCount
				bucketStr string
			)
			if err := bRows.Scan(&bucketStr, &tbc.Total, &tbc.Block); err == nil {
				if t, err := time.Parse(time.RFC3339, bucketStr); err == nil {
					tbc.Bucket = t
					stats.TimeBuckets = append(stats.TimeBuckets, tbc)
				}
			}
		}
	}

	return stats, nil
}

// aggregateWhere builds the shared timestamp and host/country predicate with
// positional placeholders starting at $1.
func aggregateWhere(start, end time.Time, filter ...telemetry.AggregateFilter) (string, []any) {
	clause := "timestamp >= $1 AND timestamp <= $2"
	args := []any{start, end}

	if len(filter) == 0 {
		return clause, args
	}

	if host := strings.TrimSpace(filter[0].Host); host != "" {
		args = append(args, host)
		clause += fmt.Sprintf(" AND host = $%d", len(args))
	}
	if country := strings.TrimSpace(filter[0].Country); country != "" {
		args = append(args, country)
		clause += fmt.Sprintf(" AND country = $%d", len(args))
	}

	return clause, args
}
