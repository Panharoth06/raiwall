package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
	"time"
)

func (s *telemetryDriverStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.conn.db.mu.RLock()
	defer s.conn.db.mu.RUnlock()

	q := s.query

	if isIncidentQuery(q) {
		if strings.Contains(q, "SELECT COUNT(*)") {
			return s.countIncidentGroups(args), nil
		}
		return s.queryIncidentGroups(args), nil
	}

	if strings.Contains(q, "SELECT COUNT(*)") && !strings.Contains(q, "COALESCE") {
		filtered := s.filterRows(args)
		return &telemetrySimpleRows{
			columns: []string{"count"},
			rows:    [][]driver.Value{{int64(len(filtered))}},
		}, nil
	}

	if strings.Contains(q, "COALESCE(SUM(CASE WHEN action IN ('block', 'ban')") {
		var total, blocked, pageViews, status4xx, status4xxBlocked, status5xx int64
		uniqueIPs := make(map[string]bool)
		blockedIPs := make(map[string]bool)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			total++
			if r.ClientIP != "" {
				uniqueIPs[r.ClientIP] = true
			}
			if r.Action == "block" || r.Action == "ban" {
				blocked++
				if r.ClientIP != "" {
					blockedIPs[r.ClientIP] = true
				}
			}
			if r.Method == "GET" && (r.StatusCode < 400 || r.StatusCode == 0) {
				pageViews++
			}
			if r.StatusCode >= 400 && r.StatusCode < 500 {
				status4xx++
			}
			if (r.StatusCode >= 400 && r.StatusCode < 500 && (r.Action == "block" || r.Action == "ban")) || r.StatusCode == 403 {
				status4xxBlocked++
			}
			if r.StatusCode >= 500 {
				status5xx++
			}
		}
		return &telemetrySimpleRows{
			columns: []string{"total", "blocked", "page_views", "unique_ips", "blocked_ips", "status_4xx", "status_4xx_blocked", "status_5xx"},
			rows:    [][]driver.Value{{total, blocked, pageViews, int64(len(uniqueIPs)), int64(len(blockedIPs)), status4xx, status4xxBlocked, status5xx}},
		}, nil
	}

	if strings.Contains(q, "GROUP BY country") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.Country != "" {
				counts[r.Country]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	if strings.Contains(q, "GROUP BY rule_id") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.RuleID != "" {
				counts[r.RuleID]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	if strings.Contains(q, "GROUP BY client_ip") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.ClientIP != "" {
				counts[r.ClientIP]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	if strings.Contains(q, "GROUP BY attack_category") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.AttackCategory != "" {
				counts[r.AttackCategory]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	if strings.Contains(q, "GROUP BY bucket") {
		type bItem struct {
			total   int64
			blocked int64
		}
		buckets := make(map[string]*bItem)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			bKey := r.Timestamp.UTC().Truncate(time.Hour).Format("2006-01-02T15:00:00Z")
			bi, ok := buckets[bKey]
			if !ok {
				bi = &bItem{}
				buckets[bKey] = bi
			}
			bi.total++
			if r.Action == "block" || r.Action == "ban" {
				bi.blocked++
			}
		}

		keys := make([]string, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		rows := make([][]driver.Value, len(keys))
		for i, k := range keys {
			rows[i] = []driver.Value{k, buckets[k].total, buckets[k].blocked}
		}
		return &telemetrySimpleRows{
			columns: []string{"bucket", "total", "blocked"},
			rows:    rows,
		}, nil
	}

	filtered := s.filterRows(args)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	limit := 50
	offset := 0
	if len(args) >= 2 {
		if l, ok := args[len(args)-2].(int64); ok {
			limit = int(l)
		} else if l, ok := args[len(args)-2].(int); ok {
			limit = l
		}
		if o, ok := args[len(args)-1].(int64); ok {
			offset = int(o)
		} else if o, ok := args[len(args)-1].(int); ok {
			offset = o
		}
	}

	startIdx := offset
	if startIdx > len(filtered) {
		startIdx = len(filtered)
	}
	endIdx := startIdx + limit
	if endIdx > len(filtered) {
		endIdx = len(filtered)
	}

	page := filtered[startIdx:endIdx]
	rows := make([][]driver.Value, len(page))
	for i, r := range page {
		rows[i] = []driver.Value{
			r.EventID,
			r.Timestamp.UTC().Format(time.RFC3339Nano),
			r.Host,
			r.Path,
			r.Method,
			r.ClientIP,
			r.JA4,
			r.Country,
			r.Continent,
			r.City,
			int64(r.ASN),
			r.ASOrg,
			r.Latitude,
			r.Longitude,
			r.RuleID,
			r.Action,
			r.Severity,
			r.Headers,
			r.Payload,
			r.LatencyUs,
			int64(r.StatusCode),
			r.PayloadLocation,
			r.MatchedToken,
			r.AttackCategory,
			r.ResponseHeaders,
			r.ResponseBody,
		}
	}

	cols := []string{
		"event_id", "timestamp", "host", "path", "method", "client_ip", "ja4",
		"country", "continent", "city", "asn", "as_org", "latitude", "longitude",
		"rule_id", "action", "severity", "headers", "payload", "latency_us", "status_code",
		"payload_location", "matched_token", "attack_category", "response_headers", "response_body",
	}

	return &telemetrySimpleRows{columns: cols, rows: rows}, nil
}
