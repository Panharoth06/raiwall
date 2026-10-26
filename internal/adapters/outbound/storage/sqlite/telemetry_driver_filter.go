package sqlite

import (
	"database/sql/driver"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *telemetryDriverStmt) buildTopCounts(counts map[string]int64) driver.Rows {
	type pair struct {
		key string
		cnt int64
	}
	pairs := make([]pair, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, pair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].cnt > pairs[j].cnt
	})
	if len(pairs) > 10 {
		pairs = pairs[:10]
	}

	rows := make([][]driver.Value, len(pairs))
	for i, p := range pairs {
		rows[i] = []driver.Value{p.key, p.cnt}
	}
	return &telemetrySimpleRows{
		columns: []string{"key", "cnt"},
		rows:    rows,
	}
}

func (s *telemetryDriverStmt) filterRows(args []driver.Value) []*telemetryDBRow {
	var result []*telemetryDBRow

	whereIdx := strings.Index(s.query, "WHERE")
	if whereIdx == -1 {
		for _, r := range s.conn.db.ordered {
			result = append(result, r)
		}
		return result
	}

	whereClause := s.query[whereIdx+5:]
	if orderIdx := strings.Index(whereClause, "ORDER BY"); orderIdx != -1 {
		whereClause = whereClause[:orderIdx]
	}

	conditions := strings.Split(whereClause, "AND")
	argIdx := 0

	var (
		startTime, endTime             time.Time
		clientIP, host, action, ruleID string
		country, severity, eventID     string
	)

	for _, cond := range conditions {
		c := strings.TrimSpace(cond)
		if strings.Contains(c, "timestamp >=") && argIdx < len(args) {
			startTime, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[argIdx]))
			if startTime.IsZero() {
				startTime, _ = time.Parse(time.RFC3339, fmt.Sprint(args[argIdx]))
			}
			argIdx++
		} else if strings.Contains(c, "timestamp <=") && argIdx < len(args) {
			endTime, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[argIdx]))
			if endTime.IsZero() {
				endTime, _ = time.Parse(time.RFC3339, fmt.Sprint(args[argIdx]))
			}
			argIdx++
		} else if strings.Contains(c, "event_id =") && argIdx < len(args) {
			eventID = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "client_ip =") && argIdx < len(args) {
			clientIP = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "host =") && argIdx < len(args) {
			host = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "action =") && argIdx < len(args) {
			action = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "rule_id =") && argIdx < len(args) {
			ruleID = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "country =") && argIdx < len(args) {
			country = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "severity =") && argIdx < len(args) {
			severity = fmt.Sprint(args[argIdx])
			argIdx++
		}
	}

	for _, r := range s.conn.db.ordered {
		if eventID != "" && r.EventID != eventID {
			continue
		}
		if !startTime.IsZero() && r.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && r.Timestamp.After(endTime) {
			continue
		}
		if clientIP != "" && r.ClientIP != clientIP {
			continue
		}
		if host != "" && r.Host != host {
			continue
		}
		if action != "" && r.Action != action {
			continue
		}
		if ruleID != "" && r.RuleID != ruleID {
			continue
		}
		if country != "" && r.Country != country {
			continue
		}
		if severity != "" && r.Severity != severity {
			continue
		}
		result = append(result, r)
	}

	return result
}
