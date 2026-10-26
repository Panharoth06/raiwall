package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

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
