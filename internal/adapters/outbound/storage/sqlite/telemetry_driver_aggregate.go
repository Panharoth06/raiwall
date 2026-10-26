package sqlite

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

// telemetryAggregateFilter mirrors the predicate built by QueryAggregates:
// timestamp bounds first, then optional host and country arguments.
type telemetryAggregateFilter struct {
	start   time.Time
	end     time.Time
	host    string
	country string
}

func (s *telemetryDriverStmt) parseAggregateFilter(args []driver.Value) telemetryAggregateFilter {
	f := telemetryAggregateFilter{}
	if len(args) > 0 {
		f.start = parseTelemetryTime(args[0])
	}
	if len(args) > 1 {
		f.end = parseTelemetryTime(args[1])
	}

	idx := 2
	where := s.query
	if i := strings.Index(where, "WHERE"); i >= 0 {
		where = where[i:]
	}
	if strings.Contains(where, "host = ?") && idx < len(args) {
		f.host = fmt.Sprint(args[idx])
		idx++
	}
	if strings.Contains(where, "country = ?") && idx < len(args) {
		f.country = fmt.Sprint(args[idx])
	}

	return f
}

func (f telemetryAggregateFilter) matches(r *telemetryDBRow) bool {
	if !f.start.IsZero() && r.Timestamp.Before(f.start) {
		return false
	}
	if !f.end.IsZero() && r.Timestamp.After(f.end) {
		return false
	}
	if f.host != "" && r.Host != f.host {
		return false
	}
	if f.country != "" && r.Country != f.country {
		return false
	}
	return true
}

func parseTelemetryTime(value driver.Value) time.Time {
	raw := fmt.Sprint(value)
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	t, _ := time.Parse(time.RFC3339, raw)
	return t
}

func isBlockedAction(action string) bool {
	return action == "block" || action == "ban"
}

// bucketGranularity mirrors the adaptive strftime format chosen by the
// telemetry adapter: minutes for <= 2h windows, days for > 48h, otherwise hours.
func bucketGranularity(query string) time.Duration {
	switch {
	case strings.Contains(query, "%M:00Z"):
		return time.Minute
	case strings.Contains(query, "T00:00:00Z"):
		return 24 * time.Hour
	default:
		return time.Hour
	}
}
