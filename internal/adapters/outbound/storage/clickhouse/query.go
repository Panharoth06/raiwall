package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// Query performs a filtered historical query in ClickHouse.
func (s *ClickHouseStore) Query(ctx context.Context, params telemetry.QueryParams) (*telemetry.QueryResult, error) {
	whereClauses := []string{"1=1"}
	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp >= '%s'", params.StartTime.UTC().Format("2006-01-02 15:04:05.000")))
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp <= '%s'", params.EndTime.UTC().Format("2006-01-02 15:04:05.000")))
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("client_ip = '%s'", escapeCH(params.ClientIP)))
	}
	if params.Action != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("action = '%s'", escapeCH(params.Action)))
	}
	if params.RuleID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("rule_id = '%s'", escapeCH(params.RuleID)))
	}
	if params.Country != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("country = '%s'", escapeCH(params.Country)))
	}
	if params.MinSeverity != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("severity = '%s'", escapeCH(params.MinSeverity)))
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countSQL := fmt.Sprintf("SELECT count() FROM %s.%s WHERE %s FORMAT JSON", s.database, s.table, whereSQL)
	countResp, err := s.execWithRetry(ctx, countSQL, nil)
	if err != nil {
		return nil, fmt.Errorf("count query: %w", err)
	}

	var countData struct {
		Data []struct {
			Count string `json:"count()"`
		} `json:"data"`
	}
	_ = json.Unmarshal(countResp, &countData)
	var total int64
	if len(countData.Data) > 0 {
		fmt.Sscanf(countData.Data[0].Count, "%d", &total)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchSQL := fmt.Sprintf(`
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code
		FROM %s.%s
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d
		FORMAT JSON
	`, s.database, s.table, whereSQL, limit, offset)

	fetchResp, err := s.execWithRetry(ctx, fetchSQL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch query: %w", err)
	}

	var queryData struct {
		Data []struct {
			EventID    string  `json:"event_id"`
			Timestamp  string  `json:"timestamp"`
			Host       string  `json:"host"`
			Path       string  `json:"path"`
			Method     string  `json:"method"`
			ClientIP   string  `json:"client_ip"`
			JA4        string  `json:"ja4"`
			Country    string  `json:"country"`
			Continent  string  `json:"continent"`
			City       string  `json:"city"`
			ASN        uint    `json:"asn"`
			ASOrg      string  `json:"as_org"`
			Latitude   float64 `json:"latitude"`
			Longitude  float64 `json:"longitude"`
			RuleID     string  `json:"rule_id"`
			Action     string  `json:"action"`
			Severity   string  `json:"severity"`
			Headers    string  `json:"headers"`
			Payload    string  `json:"payload"`
			LatencyUs  int64   `json:"latency_us"`
			StatusCode int     `json:"status_code"`
		} `json:"data"`
	}
	_ = json.Unmarshal(fetchResp, &queryData)

	events := make([]*telemetry.ForensicEvent, 0, len(queryData.Data))
	for _, row := range queryData.Data {
		ts, _ := time.Parse("2006-01-02 15:04:05.000", row.Timestamp)
		var hMap map[string]string
		if row.Headers != "" {
			_ = json.Unmarshal([]byte(row.Headers), &hMap)
		}

		events = append(events, &telemetry.ForensicEvent{
			EventID:   row.EventID,
			Timestamp: ts,
			Host:      row.Host,
			Path:      row.Path,
			Method:    row.Method,
			ClientIP:  row.ClientIP,
			JA4:       row.JA4,
			GeoData: telemetry.GeoData{
				Country:   row.Country,
				Continent: row.Continent,
				City:      row.City,
				ASN:       row.ASN,
				ASOrg:     row.ASOrg,
				Latitude:  row.Latitude,
				Longitude: row.Longitude,
			},
			RuleID:           row.RuleID,
			Action:           row.Action,
			Severity:         row.Severity,
			Headers:          hMap,
			TruncatedPayload: row.Payload,
			Latency:          time.Duration(row.LatencyUs) * time.Microsecond,
			StatusCode:       row.StatusCode,
		})
	}

	return &telemetry.QueryResult{
		Events: events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetEventByID retrieves a single event from ClickHouse by ID.
func (s *ClickHouseStore) GetEventByID(ctx context.Context, eventID string) (*telemetry.ForensicEvent, error) {
	res, err := s.Query(ctx, telemetry.QueryParams{Limit: 50})
	if err != nil {
		return nil, err
	}
	for _, e := range res.Events {
		if e.EventID == eventID {
			return e, nil
		}
	}
	return nil, nil
}
