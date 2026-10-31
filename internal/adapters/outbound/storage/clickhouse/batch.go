package clickhouse

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// SaveBatch persists a batch of events using native high-performance JSONEachRow streaming.
func (s *ClickHouseStore) SaveBatch(ctx context.Context, events []*telemetry.ForensicEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, e := range events {
		var headersStr, respHeadersStr, matchedRulesStr string
		if len(e.Headers) > 0 {
			if b, err := json.Marshal(e.Headers); err == nil {
				headersStr = string(b)
			}
		}
		if len(e.ResponseHeaders) > 0 {
			if b, err := json.Marshal(e.ResponseHeaders); err == nil {
				respHeadersStr = string(b)
			}
		}
		if len(e.MatchedRules) > 0 {
			if b, err := json.Marshal(e.MatchedRules); err == nil {
				matchedRulesStr = string(b)
			}
		}

		record := map[string]interface{}{
			"event_id":         e.EventID,
			"timestamp":        e.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			"host":             e.Host,
			"path":             e.Path,
			"method":           e.Method,
			"client_ip":        e.ClientIP,
			"ja4":              e.JA4,
			"country":          e.GeoData.Country,
			"continent":        e.GeoData.Continent,
			"city":             e.GeoData.City,
			"asn":              e.GeoData.ASN,
			"as_org":           e.GeoData.ASOrg,
			"latitude":         e.GeoData.Latitude,
			"longitude":        e.GeoData.Longitude,
			"rule_id":          e.RuleID,
			"action":           e.Action,
			"severity":         e.Severity,
			"headers":          headersStr,
			"payload":          e.TruncatedPayload,
			"latency_us":       e.Latency.Microseconds(),
			"status_code":      e.StatusCode,
			"payload_location": e.PayloadLocation,
			"matched_token":    e.MatchedToken,
			"attack_category":  e.AttackCategory,
			"response_headers": respHeadersStr,
			"response_body":    base64.StdEncoding.EncodeToString(e.ResponseBody),
			"engine":           e.Engine,
			"anomaly_score":    e.AnomalyScore,
			"paranoia_level":   e.ParanoiaLevel,
			"matched_rules":    matchedRulesStr,
		}

		line, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal ch record: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", s.database, s.table)
	_, err := s.execWithRetry(ctx, query, &buf)
	return err
}
