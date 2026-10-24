package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// QueryAggregates computes summary metrics and top aggregations across a time interval.
func (s *TelemetryStore) QueryAggregates(ctx context.Context, start, end time.Time, filter ...telemetry.AggregateFilter) (*telemetry.AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startStr := start.UTC().Format(time.RFC3339Nano)
	endStr := end.UTC().Format(time.RFC3339Nano)

	stats := &telemetry.AggregateStats{
		TimeBuckets:   make([]telemetry.TimeBucketCount, 0),
		TopCountries:  make([]telemetry.TopCount, 0),
		TopRules:      make([]telemetry.TopCount, 0),
		TopIPs:        make([]telemetry.TopCount, 0),
		TopCategories: make([]telemetry.TopCount, 0),
	}

	whereClause := "timestamp >= ? AND timestamp <= ?"
	args := []interface{}{startStr, endStr}

	if len(filter) > 0 {
		if filter[0].Host != "" {
			whereClause += " AND host = ?"
			args = append(args, filter[0].Host)
		}
		if filter[0].Country != "" {
			whereClause += " AND country = ?"
			args = append(args, filter[0].Country)
		}
	}

	totalQuery := fmt.Sprintf(`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN (method = 'GET' OR method = '') AND (status_code < 400 OR status_code IS NULL OR status_code = 0) AND action NOT IN ('block', 'ban') THEN 1 ELSE 0 END), 0),
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
		return nil, fmt.Errorf("query totals: %w", err)
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

	// Calculate live QPS in last 10 seconds
	qpsStartStr := time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
	qpsQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ? %s
	`, strings.TrimPrefix(whereClause, "timestamp >= ? AND timestamp <= ?"))
	qpsArgs := append([]interface{}{qpsStartStr, time.Now().UTC().Format(time.RFC3339Nano)}, args[2:]...)
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

	catQuery := fmt.Sprintf(`
		SELECT attack_category, COUNT(*) as cnt
		FROM forensic_events
		WHERE %s AND attack_category != ''
		GROUP BY attack_category
		ORDER BY cnt DESC
		LIMIT 10
	`, whereClause)
	if catRows, err := s.db.QueryContext(ctx, catQuery, args...); err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var tc telemetry.TopCount
			if err := catRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopCategories = append(stats.TopCategories, tc)
			}
		}
	}

	// Adaptive bucket format based on window duration
	bucketFormat := "%Y-%m-%dT%H:00:00Z"
	duration := end.Sub(start)
	if duration <= 2*time.Hour {
		bucketFormat = "%Y-%m-%dT%H:%M:00Z"
	} else if duration > 48*time.Hour {
		bucketFormat = "%Y-%m-%dT00:00:00Z"
	}

	bucketQuery := fmt.Sprintf(`
		SELECT strftime('%s', timestamp) as bucket,
		       COUNT(*) as total,
		       SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END) as blocked
		FROM forensic_events
		WHERE %s
		GROUP BY bucket
		ORDER BY bucket ASC
	`, bucketFormat, whereClause)
	if bRows, err := s.db.QueryContext(ctx, bucketQuery, args...); err == nil {
		defer bRows.Close()
		for bRows.Next() {
			var (
				bucketStr string
				total     int64
				blocked   int64
			)
			if err := bRows.Scan(&bucketStr, &total, &blocked); err == nil {
				if t, err := time.Parse(time.RFC3339, bucketStr); err == nil {
					stats.TimeBuckets = append(stats.TimeBuckets, telemetry.TimeBucketCount{
						Bucket: t,
						Total:  total,
						Block:  blocked,
					})
				}
			}
		}
	}

	return stats, nil
}

// GetAggregatedIncidents groups events occurring within a sliding 5-minute window by client_ip and host.
func (s *TelemetryStore) GetAggregatedIncidents(ctx context.Context, params telemetry.IncidentQueryParams) (*telemetry.IncidentQueryResult, error) {
	whereClauses := []string{"1=1"}
	args := []interface{}{}

	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, params.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, params.EndTime.UTC().Format(time.RFC3339Nano))
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, "client_ip = ?")
		args = append(args, params.ClientIP)
	}
	if params.Host != "" {
		whereClauses = append(whereClauses, "host = ?")
		args = append(args, params.Host)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			SELECT 1 FROM forensic_events
			WHERE %s
			GROUP BY client_ip, host, (CAST(strftime('%%%%s', timestamp) AS INTEGER) / 300)
		)
	`, whereSQL)

	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("incident count query: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchQuery := fmt.Sprintf(`
		SELECT 
			client_ip,
			host,
			(CAST(strftime('%%%%s', timestamp) AS INTEGER) / 300) as time_window,
			MIN(timestamp) as min_ts,
			MAX(timestamp) as max_ts,
			COUNT(*) as total_events,
			SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END) as total_blocked,
			CASE MAX(CASE severity
				WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
				WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)
				WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium'
				WHEN 2 THEN 'low' WHEN 1 THEN 'info' ELSE '' END as max_severity,
			MAX(rule_id) as top_rule,
			COALESCE(MAX(attack_category), '') as category,
			COALESCE(MAX(country), '') as country
		FROM forensic_events
		WHERE %s
		GROUP BY client_ip, host, time_window
		ORDER BY min_ts DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("fetch incidents query: %w", err)
	}
	defer rows.Close()

	var incidents []*telemetry.Incident
	for rows.Next() {
		var (
			inc        telemetry.Incident
			timeWindow int64
			minTsStr   string
			maxTsStr   string
		)
		err := rows.Scan(
			&inc.ClientIP,
			&inc.Host,
			&timeWindow,
			&minTsStr,
			&maxTsStr,
			&inc.TotalEvents,
			&inc.TotalBlocked,
			&inc.MaxSeverity,
			&inc.TopRuleID,
			&inc.Category,
			&inc.Country,
		)
		if err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}

		if t, err := time.Parse(time.RFC3339Nano, minTsStr); err == nil {
			inc.StartTime = t
		}
		if t, err := time.Parse(time.RFC3339Nano, maxTsStr); err == nil {
			inc.EndTime = t
		}
		inc.ID = fmt.Sprintf("inc-%s-%s-%d", inc.ClientIP, inc.Host, timeWindow)
		if inc.Category == "" {
			inc.Category = inc.TopRuleID
		}
		incidents = append(incidents, &inc)
	}

	return &telemetry.IncidentQueryResult{
		Incidents:  incidents,
		TotalCount: total,
	}, nil
}
