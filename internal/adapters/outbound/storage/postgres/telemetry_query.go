package postgres

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
	if params.Action != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, params.Action)
		argIdx++
	}
	if params.RuleID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("rule_id = $%d", argIdx))
		args = append(args, params.RuleID)
		argIdx++
	}
	if params.Country != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("country = $%d", argIdx))
		args = append(args, params.Country)
		argIdx++
	}
	if params.MinSeverity != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, params.MinSeverity)
		argIdx++
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM forensic_events WHERE %s", whereSQL)
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count postgres events: %w", err)
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
		SELECT event_id, timestamp,
		       COALESCE(host, '') AS host,
		       COALESCE(path, '') AS path,
		       COALESCE(method, '') AS method,
		       COALESCE(client_ip, '') AS client_ip,
		       COALESCE(ja4, '') AS ja4,
		       COALESCE(country, '') AS country,
		       COALESCE(continent, '') AS continent,
		       COALESCE(city, '') AS city,
		       COALESCE(asn, 0) AS asn,
		       COALESCE(as_org, '') AS as_org,
		       COALESCE(latitude, 0.0) AS latitude,
		       COALESCE(longitude, 0.0) AS longitude,
		       COALESCE(rule_id, '') AS rule_id,
		       COALESCE(action, '') AS action,
		       COALESCE(severity, '') AS severity,
		       COALESCE(headers, '') AS headers,
		       COALESCE(payload, '') AS payload,
		       COALESCE(latency_us, 0) AS latency_us,
		       COALESCE(status_code, 0) AS status_code,
		       COALESCE(payload_location, '') AS payload_location,
		       COALESCE(matched_token, '') AS matched_token,
		       COALESCE(attack_category, '') AS attack_category,
		       COALESCE(response_headers, '') AS response_headers,
		       COALESCE(response_body, ''::bytea) AS response_body
		FROM forensic_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, argIdx, argIdx+1)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("query postgres events: %w", err)
	}
	defer rows.Close()

	var events []*telemetry.ForensicEvent
	for rows.Next() {
		var (
			e               telemetry.ForensicEvent
			headersJSON     string
			respHeadersJSON string
			latencyUs       int64
		)
		err := rows.Scan(
			&e.EventID,
			&e.Timestamp,
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
		)
		if err != nil {
			return nil, fmt.Errorf("scan postgres event: %w", err)
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

// GetEventByID retrieves a single forensic event by its UUID from PostgreSQL.
func (s *TelemetryStore) GetEventByID(ctx context.Context, eventID string) (*telemetry.ForensicEvent, error) {
	query := `
		SELECT event_id, timestamp,
		       COALESCE(host, ''),
		       COALESCE(path, ''),
		       COALESCE(method, ''),
		       COALESCE(client_ip, ''),
		       COALESCE(ja4, ''),
		       COALESCE(country, ''),
		       COALESCE(continent, ''),
		       COALESCE(city, ''),
		       COALESCE(asn, 0),
		       COALESCE(as_org, ''),
		       COALESCE(latitude, 0.0),
		       COALESCE(longitude, 0.0),
		       COALESCE(rule_id, ''),
		       COALESCE(action, ''),
		       COALESCE(severity, ''),
		       COALESCE(headers, ''),
		       COALESCE(payload, ''),
		       COALESCE(latency_us, 0),
		       COALESCE(status_code, 0),
		       COALESCE(payload_location, ''),
		       COALESCE(matched_token, ''),
		       COALESCE(attack_category, ''),
		       COALESCE(response_headers, ''),
		       COALESCE(response_body, ''::bytea)
		FROM forensic_events
		WHERE event_id = $1
		LIMIT 1
	`
	row := s.db.QueryRowContext(ctx, query, eventID)
	var (
		e               telemetry.ForensicEvent
		headersJSON     string
		respHeadersJSON string
		latencyUs       int64
	)
	err := row.Scan(
		&e.EventID, &e.Timestamp, &e.Host, &e.Path, &e.Method, &e.ClientIP, &e.JA4,
		&e.GeoData.Country, &e.GeoData.Continent, &e.GeoData.City, &e.GeoData.ASN, &e.GeoData.ASOrg,
		&e.GeoData.Latitude, &e.GeoData.Longitude,
		&e.RuleID, &e.Action, &e.Severity, &headersJSON, &e.TruncatedPayload,
		&latencyUs, &e.StatusCode,
		&e.PayloadLocation, &e.MatchedToken, &e.AttackCategory,
		&respHeadersJSON, &e.ResponseBody,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get event by id %s: %w", eventID, err)
	}

	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &e.Headers)
	}
	if respHeadersJSON != "" {
		_ = json.Unmarshal([]byte(respHeadersJSON), &e.ResponseHeaders)
	}
	e.Latency = time.Duration(latencyUs) * time.Microsecond
	return &e, nil
}
