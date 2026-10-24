package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
	"time"
)

// telemetryIncidentGroup is the in-memory equivalent of one 5-minute incident cluster.
type telemetryIncidentGroup struct {
	ClientIP    string
	Host        string
	Window      int64
	MinTS       time.Time
	MaxTS       time.Time
	Total       int64
	Blocked     int64
	MaxSeverity string
	TopRule     string
	Category    string
	Country     string
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func severityFromRank(rank int) string {
	switch rank {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	case 1:
		return "info"
	default:
		return ""
	}
}

// isIncidentQuery reports whether the statement aggregates events into 5-minute incident windows.
func isIncidentQuery(q string) bool {
	return strings.Contains(q, "GROUP BY client_ip, host")
}

// incidentGroups builds 5-minute incident clusters from the WHERE-filtered rows.
func (s *telemetryDriverStmt) incidentGroups(args []driver.Value) []*telemetryIncidentGroup {
	filtered := s.filterRows(args)
	index := make(map[string]*telemetryIncidentGroup)
	order := make([]string, 0, len(filtered))

	for _, r := range filtered {
		window := r.Timestamp.Unix() / 300
		key := r.ClientIP + "\x00" + r.Host + "\x00" + time.Unix(window*300, 0).UTC().Format(time.RFC3339)
		group, ok := index[key]
		if !ok {
			group = &telemetryIncidentGroup{
				ClientIP: r.ClientIP,
				Host:     r.Host,
				Window:   window,
				MinTS:    r.Timestamp,
				MaxTS:    r.Timestamp,
			}
			index[key] = group
			order = append(order, key)
		}
		if r.Timestamp.Before(group.MinTS) {
			group.MinTS = r.Timestamp
		}
		if r.Timestamp.After(group.MaxTS) {
			group.MaxTS = r.Timestamp
		}
		group.Total++
		if r.Action == "block" || r.Action == "ban" {
			group.Blocked++
		}
		if severityRank(r.Severity) > severityRank(group.MaxSeverity) {
			group.MaxSeverity = r.Severity
		}
		if r.RuleID > group.TopRule {
			group.TopRule = r.RuleID
		}
		if r.AttackCategory > group.Category {
			group.Category = r.AttackCategory
		}
		if r.Country > group.Country {
			group.Country = r.Country
		}
	}

	groups := make([]*telemetryIncidentGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, index[key])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].MinTS.After(groups[j].MinTS)
	})
	return groups
}

// countIncidentGroups answers the incident total-count wrapping query.
func (s *telemetryDriverStmt) countIncidentGroups(args []driver.Value) driver.Rows {
	groups := s.incidentGroups(args)
	return &telemetrySimpleRows{
		columns: []string{"count"},
		rows:    [][]driver.Value{{int64(len(groups))}},
	}
}

// queryIncidentGroups answers the paginated incident listing query.
func (s *telemetryDriverStmt) queryIncidentGroups(args []driver.Value) driver.Rows {
	groups := s.incidentGroups(args)

	limit, offset := 20, 0
	if strings.Contains(s.query, "LIMIT ? OFFSET ?") && len(args) >= 2 {
		limit = trailingInt(args[len(args)-2], limit)
		offset = trailingInt(args[len(args)-1], offset)
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(groups) {
		offset = len(groups)
	}
	end := offset + limit
	if end > len(groups) {
		end = len(groups)
	}

	page := groups[offset:end]
	rows := make([][]driver.Value, len(page))
	for i, g := range page {
		category := g.Category
		if category == "" {
			category = g.TopRule
		}
		rows[i] = []driver.Value{
			g.ClientIP,
			g.Host,
			g.Window,
			g.MinTS.UTC().Format(time.RFC3339Nano),
			g.MaxTS.UTC().Format(time.RFC3339Nano),
			g.Total,
			g.Blocked,
			g.MaxSeverity,
			g.TopRule,
			category,
			g.Country,
		}
	}

	return &telemetrySimpleRows{
		columns: []string{
			"client_ip", "host", "time_window", "min_ts", "max_ts",
			"total_events", "total_blocked", "max_severity", "top_rule", "category", "country",
		},
		rows: rows,
	}
}

func trailingInt(v driver.Value, fallback int) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		return fallback
	}
}
