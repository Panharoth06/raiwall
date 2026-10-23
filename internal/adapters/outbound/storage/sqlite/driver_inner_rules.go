package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
	"time"
)

// Inner Rules (virtual-patch signature toggles): row presence = disabled.
// The in-memory driver mirrors the schema table raiwall_inner_rule_disabled.

func (s *controlStmt) execInnerRules(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	if strings.Contains(q, "INSERT INTO raiwall_inner_rule_disabled") ||
		strings.Contains(q, "REPLACE INTO raiwall_inner_rule_disabled") {
		st.innerRuleDisabled[toStringVal(args[0])] = time.Now().UTC()
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_inner_rule_disabled WHERE rule_id = ?") {
		delete(st.innerRuleDisabled, toStringVal(args[0]))
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_inner_rule_disabled") {
		st.innerRuleDisabled = make(map[string]time.Time)
		return driver.RowsAffected(1), true
	}
	return nil, false
}

func (s *controlStmt) queryInnerRules(st *databaseState, q string, _ []driver.Value) (driver.Rows, bool) {
	if strings.Contains(q, "FROM raiwall_inner_rule_disabled") {
		ids := make([]string, 0, len(st.innerRuleDisabled))
		for id := range st.innerRuleDisabled {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		data := make([][]driver.Value, 0, len(ids))
		for _, id := range ids {
			data = append(data, []driver.Value{id})
		}
		return &driverMemoryRows{
			columns: []string{"rule_id"},
			data:    data,
		}, true
	}
	return nil, false
}
