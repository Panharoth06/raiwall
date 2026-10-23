package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

// Per-app auth gate state: portal-wide settings and the authentication audit log.

var settingsCols = []string{"key", "value", "updated_at"}

var authLogCols = []string{
	"created_at", "username", "app_id", "host", "method",
	"result", "client_ip", "country", "detail",
}

func authEventRow(e *RaiwallIdentityAuthEvent) []driver.Value {
	return []driver.Value{e.CreatedAt, e.Username, e.AppID, e.Host, e.Method,
		e.Result, e.ClientIP, e.Country, e.Detail}
}

func (s *controlStmt) execAuthGate(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	if strings.Contains(q, "INSERT OR REPLACE INTO raiwall_settings") ||
		strings.Contains(q, "INSERT INTO raiwall_settings") {
		st.settings[toStringVal(args[0])] = toStringVal(args[1])
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "INSERT OR REPLACE INTO raiwall_identity_auth_log") ||
		strings.Contains(q, "INSERT INTO raiwall_identity_auth_log") {
		st.authLog = append(st.authLog, &RaiwallIdentityAuthEvent{
			CreatedAt: toTime(args[0]),
			Username:  toStringVal(args[1]),
			AppID:     toStringVal(args[2]),
			Host:      toStringVal(args[3]),
			Method:    toStringVal(args[4]),
			Result:    toStringVal(args[5]),
			ClientIP:  toStringVal(args[6]),
			Country:   toStringVal(args[7]),
			Detail:    toStringVal(args[8]),
		})
		return driver.RowsAffected(1), true
	}
	return nil, false
}

func (s *controlStmt) queryAuthGate(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	if strings.Contains(q, "FROM raiwall_settings") {
		key := toStringVal(args[0])
		value, ok := st.settings[key]
		if !ok {
			return &driverMemoryRows{columns: []string{"value"}, data: nil}, true
		}
		return &driverMemoryRows{
			columns: []string{"value"},
			data:    [][]driver.Value{{value}},
		}, true
	}
	if strings.Contains(q, "FROM raiwall_identity_auth_log") {
		limit := len(st.authLog)
		if len(args) > 0 {
			if n, ok := args[0].(int64); ok && n >= 0 && int(n) < limit {
				limit = int(n)
			}
		}
		events := make([]*RaiwallIdentityAuthEvent, len(st.authLog))
		copy(events, st.authLog)
		// ORDER BY created_at DESC
		sort.Slice(events, func(i, j int) bool {
			return events[i].CreatedAt.After(events[j].CreatedAt)
		})
		if limit < len(events) {
			events = events[:limit]
		}
		data := make([][]driver.Value, 0, len(events))
		for _, e := range events {
			data = append(data, authEventRow(e))
		}
		return &driverMemoryRows{columns: authLogCols, data: data}, true
	}
	return nil, false
}
