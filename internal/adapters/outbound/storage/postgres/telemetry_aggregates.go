package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// QueryAggregates computes summary metrics and top aggregations across a time interval using PostgreSQL.
func (s *TelemetryStore) QueryAggregates(ctx context.Context, start, end time.Time) (*telemetry.AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startUTC := start.UTC()
	endUTC := end.UTC()

	stats := &telemetry.AggregateStats{
		TimeBuckets:  make([]telemetry.TimeBucketCount, 0),
		TopCountries: make([]telemetry.TopCount, 0),
		TopRules:     make([]telemetry.TopCount, 0),
		TopIPs:       make([]telemetry.TopCount, 0),
	}

	totalQuery := `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0)
		FROM forensic_events
		WHERE timestamp >= $1 AND timestamp <= $2
	`
	if err := s.db.QueryRowContext(ctx, totalQuery, startUTC, endUTC).Scan(&stats.TotalRequests, &stats.TotalBlocked); err != nil {
		return nil, fmt.Errorf("query postgres totals: %w", err)
	}

	if stats.TotalRequests > 0 {
		stats.BlockRatio = float64(stats.TotalBlocked) / float64(stats.TotalRequests)
	}

	countryQuery := `
		SELECT country, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= $1 AND timestamp <= $2 AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
	`
	if cRows, err := s.db.QueryContext(ctx, countryQuery, startUTC, endUTC); err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var tc telemetry.TopCount
			if err := cRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopCountries = append(stats.TopCountries, tc)
			}
		}
	}

	ruleQuery := `
		SELECT rule_id, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= $1 AND timestamp <= $2 AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
	`
	if rRows, err := s.db.QueryContext(ctx, ruleQuery, startUTC, endUTC); err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var tc telemetry.TopCount
			if err := rRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopRules = append(stats.TopRules, tc)
			}
		}
	}

	ipQuery := `
		SELECT client_ip, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= $1 AND timestamp <= $2 AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
	`
	if ipRows, err := s.db.QueryContext(ctx, ipQuery, startUTC, endUTC); err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var tc telemetry.TopCount
			if err := ipRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopIPs = append(stats.TopIPs, tc)
			}
		}
	}

	bucketQuery := `
		SELECT to_char(date_trunc('hour', timestamp AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:00:00"Z"') as bucket,
		       COUNT(*) as total,
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0) as blocked
		FROM forensic_events
		WHERE timestamp >= $1 AND timestamp <= $2
		GROUP BY 1
		ORDER BY bucket ASC
	`
	if bRows, err := s.db.QueryContext(ctx, bucketQuery, startUTC, endUTC); err == nil {
		defer bRows.Close()
		for bRows.Next() {
			var (
				tbc       telemetry.TimeBucketCount
				bucketStr string
			)
			if err := bRows.Scan(&bucketStr, &tbc.Total, &tbc.Block); err == nil {
				if t, err := time.Parse(time.RFC3339, bucketStr); err == nil {
					tbc.Bucket = t
				}
				stats.TimeBuckets = append(stats.TimeBuckets, tbc)
			}
		}
	}

	return stats, nil
}

// GetAggregatedIncidents groups events occurring within a sliding 5-minute window by client_ip and host.
func (s *TelemetryStore) GetAggregatedIncidents(ctx context.Context, params telemetry.IncidentQueryParams) (*telemetry.IncidentQueryResult, error) {
	whereClauses := []string{"1=1"}
	var args []any
	argIdx := 1

	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, params.StartTime.UTC())
		argIdx++
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, params.EndTime.UTC())
		argIdx++
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("client_ip = $%d", argIdx))
		args = append(args, params.ClientIP)
		argIdx++
	}
	if params.Host != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("host = $%d", argIdx))
		args = append(args, params.Host)
		argIdx++
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			SELECT 1 FROM forensic_events
			WHERE %s
			GROUP BY client_ip, host, FLOOR(EXTRACT(EPOCH FROM timestamp) / 300)
		) sub
	`, whereSQL)

	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("postgres incident count query: %w", err)
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
			FLOOR(EXTRACT(EPOCH FROM timestamp) / 300)::bigint as time_window,
			MIN(timestamp) as min_ts,
			MAX(timestamp) as max_ts,
			COUNT(*) as total_events,
			COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0) as total_blocked,
			COALESCE(MAX(severity), '') as max_severity,
			COALESCE(MAX(rule_id), '') as top_rule,
			COALESCE(MAX(attack_category), '') as category,
			COALESCE(MAX(country), '') as country
		FROM forensic_events
		WHERE %s
		GROUP BY client_ip, host, FLOOR(EXTRACT(EPOCH FROM timestamp) / 300)
		ORDER BY min_ts DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, argIdx, argIdx+1)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("fetch postgres incidents query: %w", err)
	}
	defer rows.Close()

	var incidents []*telemetry.Incident
	for rows.Next() {
		var (
			inc        telemetry.Incident
			timeWindow int64
			minTs      time.Time
			maxTs      time.Time
		)
		err := rows.Scan(
			&inc.ClientIP,
			&inc.Host,
			&timeWindow,
			&minTs,
			&maxTs,
			&inc.TotalEvents,
			&inc.TotalBlocked,
			&inc.MaxSeverity,
			&inc.TopRuleID,
			&inc.Category,
			&inc.Country,
		)
		if err != nil {
			return nil, fmt.Errorf("scan postgres incident: %w", err)
		}

		inc.StartTime = minTs
		inc.EndTime = maxTs
		inc.ID = fmt.Sprintf("inc-%s-%s-%d", inc.ClientIP, inc.Host, timeWindow)

		incidents = append(incidents, &inc)
	}

	return &telemetry.IncidentQueryResult{
		Incidents:  incidents,
		TotalCount: total,
	}, nil
}
