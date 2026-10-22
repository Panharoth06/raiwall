package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

func (s *controlStmt) Query(args []driver.Value) (driver.Rows, error) {
	st := s.getTargetState()
	st.mu.Lock()
	defer st.mu.Unlock()

	q := strings.TrimSpace(s.query)

	if rows, handled := s.queryCore(st, q, args); handled {
		return rows, nil
	}
	if rows, handled := s.queryMore(st, q, args); handled {
		return rows, nil
	}
	if rows, handled := s.queryExtra(st, q, args); handled {
		return rows, nil
	}
	if rows, handled := s.queryPhase7(st, q, args); handled {
		return rows, nil
	}

	return &driverMemoryRows{}, nil
}

func (s *controlStmt) queryCore(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	// Snapshots Create with RETURNING
	if strings.Contains(q, "INSERT INTO raiwall_config_snapshots") && strings.Contains(q, "RETURNING") {
		ver := st.nextVersion
		st.nextVersion++
		snap := &RaiwallConfigSnapshot{
			Version:      ver,
			SnapshotData: toStringVal(args[0]),
			Author:       toStringVal(args[1]),
			Description:  toStringVal(args[2]),
			CreatedAt:    toTime(args[3]),
		}
		st.snapshots = append(st.snapshots, snap)
		return &driverMemoryRows{
			columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
			data: [][]driver.Value{
				{snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt},
			},
		}, true
	}

	// raiwall_apps
	if strings.Contains(q, "FROM raiwall_apps WHERE id = ?") {
		id := toStringVal(args[0])
		if app, ok := st.apps[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "hostnames", "mode", "upstreams", "block_status_code",
					"block_response_body", "offline_status_code", "offline_response_body",
					"custom_headers", "proxy_settings", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						app.ID, app.Name, app.Hostnames, app.Mode, app.Upstreams,
						app.BlockStatusCode, app.BlockResponseBody, app.OfflineStatusCode,
						app.OfflineResponseBody, app.CustomHeaders, app.ProxySettings, app.CreatedAt, app.UpdatedAt,
					},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_apps ORDER BY name ASC") {
		list := make([]*RaiwallApp, 0, len(st.apps))
		for _, a := range st.apps {
			list = append(list, a)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Name < list[j].Name
		})
		rows := make([][]driver.Value, len(list))
		for i, app := range list {
			rows[i] = []driver.Value{
				app.ID, app.Name, app.Hostnames, app.Mode, app.Upstreams,
				app.BlockStatusCode, app.BlockResponseBody, app.OfflineStatusCode,
				app.OfflineResponseBody, app.CustomHeaders, app.ProxySettings, app.CreatedAt, app.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "hostnames", "mode", "upstreams", "block_status_code",
				"block_response_body", "offline_status_code", "offline_response_body",
				"custom_headers", "proxy_settings", "created_at", "updated_at",
			},
			data: rows,
		}, true
	}

	// raiwall_exceptions
	if strings.Contains(q, "FROM raiwall_exceptions WHERE id = ?") {
		id := toStringVal(args[0])
		if exc, ok := st.exceptions[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "description", "host", "path_regex", "path_prefix", "method",
					"location", "param_name", "param_regex", "rule_id", "is_active",
					"created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						exc.ID, exc.Description, exc.Host, exc.PathRegex, exc.PathPrefix,
						exc.Method, exc.Location, exc.ParamName, exc.ParamRegex, exc.RuleID,
						exc.IsActive, exc.CreatedAt, exc.UpdatedAt,
					},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_exceptions") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallException, 0)
		for _, e := range st.exceptions {
			if activeOnly && e.IsActive != 1 {
				continue
			}
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, e := range list {
			rows[i] = []driver.Value{
				e.ID, e.Description, e.Host, e.PathRegex, e.PathPrefix, e.Method,
				e.Location, e.ParamName, e.ParamRegex, e.RuleID, e.IsActive,
				e.CreatedAt, e.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "description", "host", "path_regex", "path_prefix", "method",
				"location", "param_name", "param_regex", "rule_id", "is_active",
				"created_at", "updated_at",
			},
			data: rows,
		}, true
	}

	// raiwall_acl_rules
	if strings.Contains(q, "FROM raiwall_acl_rules WHERE id = ?") {
		id := toStringVal(args[0])
		if rule, ok := st.aclRules[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "expression", "action", "priority", "status_code",
					"redirect_url", "is_active", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						rule.ID, rule.Name, rule.Expression, rule.Action, rule.Priority,
						rule.StatusCode, rule.RedirectUrl, rule.IsActive, rule.CreatedAt, rule.UpdatedAt,
					},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_acl_rules") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallAclRule, 0)
		for _, r := range st.aclRules {
			if activeOnly && r.IsActive != 1 {
				continue
			}
			list = append(list, r)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Priority != list[j].Priority {
				return list[i].Priority > list[j].Priority
			}
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, r := range list {
			rows[i] = []driver.Value{
				r.ID, r.Name, r.Expression, r.Action, r.Priority,
				r.StatusCode, r.RedirectUrl, r.IsActive, r.CreatedAt, r.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "expression", "action", "priority", "status_code",
				"redirect_url", "is_active", "created_at", "updated_at",
			},
			data: rows,
		}, true
	}

	return nil, false
}
