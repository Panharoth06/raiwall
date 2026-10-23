package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
	"time"
)

// sortedStringKeys returns the map keys in deterministic sorted order.
func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// nowValue returns the current UTC time for synthetic driver rows.
func nowValue() time.Time {
	return time.Now().UTC()
}

func (s *controlStmt) execMatrix(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	// 1. raiwall_detector_config
	if strings.Contains(q, "REPLACE INTO raiwall_detector_config") || strings.Contains(q, "INSERT INTO raiwall_detector_config") {
		st.detectorConfig[toStringVal(args[0])] = toStringVal(args[1])
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_detector_config WHERE module = ?") {
		delete(st.detectorConfig, toStringVal(args[0]))
		return driver.RowsAffected(1), true
	}

	// 2. raiwall_app_semantic_policies
	if strings.Contains(q, "REPLACE INTO raiwall_app_semantic_policies") || strings.Contains(q, "INSERT INTO raiwall_app_semantic_policies") {
		st.appSemPolicies[toStringVal(args[0])] = toStringVal(args[1])
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_app_semantic_policies WHERE app_id = ?") {
		delete(st.appSemPolicies, toStringVal(args[0]))
		return driver.RowsAffected(1), true
	}

	return nil, false
}

func (s *controlStmt) queryMatrix(st *databaseState, q string, _ []driver.Value) (driver.Rows, bool) {
	// Sort order for deterministic output
	sortedModules := sortedStringKeys(st.detectorConfig)
	sortedApps := sortedStringKeys(st.appSemPolicies)

	if strings.Contains(q, "FROM raiwall_detector_config ORDER BY module") {
		data := make([][]driver.Value, 0, len(sortedModules))
		for _, mod := range sortedModules {
			data = append(data, []driver.Value{mod, st.detectorConfig[mod], nowValue()})
		}
		return &driverMemoryRows{
			columns: []string{"module", "mode", "updated_at"},
			data:    data,
		}, true
	}

	if strings.Contains(q, "FROM raiwall_app_semantic_policies ORDER BY app_id") {
		data := make([][]driver.Value, 0, len(sortedApps))
		for _, appID := range sortedApps {
			data = append(data, []driver.Value{appID, st.appSemPolicies[appID], nowValue()})
		}
		return &driverMemoryRows{
			columns: []string{"app_id", "policy", "updated_at"},
			data:    data,
		}, true
	}

	return nil, false
}
