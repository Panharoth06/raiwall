package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// Query performs a filtered, paginated query across stored forensic events.
func (s *TelemetryStore) Query(ctx context.Context, params telemetry.QueryParams) (*telemetry.QueryResult, error) {
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
	if params.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, params.Action)
	}
	if params.RuleID != "" {
		whereClauses = append(whereClauses, "rule_id = ?")
		args = append(args, params.RuleID)
	}
	if params.Country != "" {
		whereClauses = append(whereClauses, "country = ?")
		args = append(args, params.Country)
	}
	if sevs := telemetry.SeveritiesAtLeast(params.MinSeverity); len(sevs) > 0 {
		whereClauses = append(whereClauses, "LOWER(severity) IN (?"+strings.Repeat(", ?", len(sevs)-1)+")")
		for _, sev := range sevs {
			args = append(args, sev)
		}
	}
	if params.Engine != "" {
		whereClauses = append(whereClauses, "engine = ?")
		args = append(args, params.Engine)
	}
	if params.MinAnomalyScore != nil {
		whereClauses = append(whereClauses, "COALESCE(anomaly_score, 0) >= ?")
		args = append(args, *params.MinAnomalyScore)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM forensic_events WHERE %s", whereSQL)
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count query: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchQuery := fmt.Sprintf(`
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code,
		       COALESCE(payload_location, '') AS payload_location,
		       COALESCE(matched_token, '') AS matched_token,
		       COALESCE(attack_category, '') AS attack_category,
		       COALESCE(response_headers, '') AS response_headers,
		       COALESCE(response_body, '') AS response_body,
		       COALESCE(engine, '') AS engine,
		       COALESCE(anomaly_score, 0) AS anomaly_score,
		       COALESCE(paranoia_level, 0) AS paranoia_level,
		       COALESCE(matched_rules, '') AS matched_rules
		FROM forensic_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("fetch query: %w", err)
	}
	defer rows.Close()

	var events []*telemetry.ForensicEvent
	for rows.Next() {
		var (
			e                telemetry.ForensicEvent
			tsStr            string
			headersJSON      string
			respHeadersJSON  string
			matchedRulesJSON string
			latencyUs        int64
		)
		err := rows.Scan(
			&e.EventID,
			&tsStr,
			&e.Host,
			&e.Path,
			&e.Method,
			&e.ClientIP,
			&e.JA4,
			&e.GeoData.Country,
			&e.GeoData.Continent,
			&e.GeoData.City,
			&e.GeoData.ASN,
			&e.GeoData.ASOrg,
			&e.GeoData.Latitude,
			&e.GeoData.Longitude,
			&e.RuleID,
			&e.Action,
			&e.Severity,
			&headersJSON,
			&e.TruncatedPayload,
			&latencyUs,
			&e.StatusCode,
			&e.PayloadLocation,
			&e.MatchedToken,
			&e.AttackCategory,
			&respHeadersJSON,
			&e.ResponseBody,
			&e.Engine,
			&e.AnomalyScore,
			&e.ParanoiaLevel,
			&matchedRulesJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if matchedRulesJSON != "" {
			_ = json.Unmarshal([]byte(matchedRulesJSON), &e.MatchedRules)
		}

		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			e.Timestamp = t
		}
		if headersJSON != "" {
			_ = json.Unmarshal([]byte(headersJSON), &e.Headers)
		}
		if respHeadersJSON != "" {
			_ = json.Unmarshal([]byte(respHeadersJSON), &e.ResponseHeaders)
		}
		e.Latency = time.Duration(latencyUs) * time.Microsecond
		events = append(events, &e)
	}

	return &telemetry.QueryResult{
		Events: events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetEventByID retrieves a single forensic event by its unique UUID.
func (s *TelemetryStore) GetEventByID(ctx context.Context, eventID string) (*telemetry.ForensicEvent, error) {
	query := `
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code,
		       COALESCE(payload_location, ''), COALESCE(matched_token, ''),
		       COALESCE(attack_category, ''), COALESCE(response_headers, ''),
		       COALESCE(response_body, X''),
		       COALESCE(engine, ''), COALESCE(anomaly_score, 0),
		       COALESCE(paranoia_level, 0), COALESCE(matched_rules, '')
		FROM forensic_events
		WHERE event_id = ?
		LIMIT 1
	`
	row := s.db.QueryRowContext(ctx, query, eventID)
	var (
		e                telemetry.ForensicEvent
		tsStr            string
		headersJSON      string
		respHeadersJSON  string
		matchedRulesJSON string
		latencyUs        int64
	)
	err := row.Scan(
		&e.EventID, &tsStr, &e.Host, &e.Path, &e.Method, &e.ClientIP, &e.JA4,
		&e.GeoData.Country, &e.GeoData.Continent, &e.GeoData.City, &e.GeoData.ASN, &e.GeoData.ASOrg,
		&e.GeoData.Latitude, &e.GeoData.Longitude,
		&e.RuleID, &e.Action, &e.Severity, &headersJSON, &e.TruncatedPayload,
		&latencyUs, &e.StatusCode,
		&e.PayloadLocation, &e.MatchedToken, &e.AttackCategory,
		&respHeadersJSON, &e.ResponseBody,
		&e.Engine, &e.AnomalyScore, &e.ParanoiaLevel, &matchedRulesJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get event by id %s: %w", eventID, err)
	}

	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		e.Timestamp = t
	}
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &e.Headers)
	}
	if respHeadersJSON != "" {
		_ = json.Unmarshal([]byte(respHeadersJSON), &e.ResponseHeaders)
	}
	if matchedRulesJSON != "" {
		_ = json.Unmarshal([]byte(matchedRulesJSON), &e.MatchedRules)
	}
	e.Latency = time.Duration(latencyUs) * time.Microsecond
	return &e, nil
}
