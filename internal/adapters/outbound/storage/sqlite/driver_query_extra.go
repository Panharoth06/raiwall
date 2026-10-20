package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

func (s *controlStmt) queryExtra(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	// raiwall_users
	if strings.Contains(q, "FROM raiwall_users WHERE id = ?") {
		id := toStringVal(args[0])
		if u, ok := st.users[id]; ok {
			return &driverMemoryRows{
				columns: []string{"id", "username", "password_hash", "role", "is_active", "created_at", "updated_at"},
				data: [][]driver.Value{
					{u.ID, u.Username, u.PasswordHash, u.Role, u.IsActive, u.CreatedAt, u.UpdatedAt},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_users WHERE username = ?") {
		un := toStringVal(args[0])
		for _, u := range st.users {
			if u.Username == un {
				return &driverMemoryRows{
					columns: []string{"id", "username", "password_hash", "role", "is_active", "created_at", "updated_at"},
					data: [][]driver.Value{
						{u.ID, u.Username, u.PasswordHash, u.Role, u.IsActive, u.CreatedAt, u.UpdatedAt},
					},
				}, true
			}
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_users ORDER BY username ASC") {
		list := make([]*RaiwallUser, 0, len(st.users))
		for _, u := range st.users {
			list = append(list, u)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Username < list[j].Username
		})
		rows := make([][]driver.Value, len(list))
		for i, u := range list {
			rows[i] = []driver.Value{
				u.ID, u.Username, u.PasswordHash, u.Role, u.IsActive, u.CreatedAt, u.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{"id", "username", "password_hash", "role", "is_active", "created_at", "updated_at"},
			data:    rows,
		}, true
	}

	// raiwall_api_keys
	if strings.Contains(q, "FROM raiwall_api_keys WHERE id = ?") {
		id := toStringVal(args[0])
		if k, ok := st.apiKeys[id]; ok {
			var exp, last any
			if k.ExpiresAt.Valid {
				exp = k.ExpiresAt.Time
			}
			if k.LastUsedAt.Valid {
				last = k.LastUsedAt.Time
			}
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "key_hash", "role", "expires_at", "is_active", "created_at", "last_used_at",
				},
				data: [][]driver.Value{
					{k.ID, k.Name, k.KeyHash, k.Role, exp, k.IsActive, k.CreatedAt, last},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_api_keys WHERE key_hash = ? AND is_active = 1") {
		hash := toStringVal(args[0])
		for _, k := range st.apiKeys {
			if k.KeyHash == hash && k.IsActive == 1 {
				var exp, last any
				if k.ExpiresAt.Valid {
					exp = k.ExpiresAt.Time
				}
				if k.LastUsedAt.Valid {
					last = k.LastUsedAt.Time
				}
				return &driverMemoryRows{
					columns: []string{
						"id", "name", "key_hash", "role", "expires_at", "is_active", "created_at", "last_used_at",
					},
					data: [][]driver.Value{
						{k.ID, k.Name, k.KeyHash, k.Role, exp, k.IsActive, k.CreatedAt, last},
					},
				}, true
			}
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_api_keys ORDER BY created_at DESC") {
		list := make([]*RaiwallApiKey, 0, len(st.apiKeys))
		for _, k := range st.apiKeys {
			list = append(list, k)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, k := range list {
			var exp, last any
			if k.ExpiresAt.Valid {
				exp = k.ExpiresAt.Time
			}
			if k.LastUsedAt.Valid {
				last = k.LastUsedAt.Time
			}
			rows[i] = []driver.Value{
				k.ID, k.Name, k.KeyHash, k.Role, exp, k.IsActive, k.CreatedAt, last,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "key_hash", "role", "expires_at", "is_active", "created_at", "last_used_at",
			},
			data: rows,
		}, true
	}

	// raiwall_forwarding_rules
	if strings.Contains(q, "FROM raiwall_forwarding_rules WHERE id = ?") {
		id := toStringVal(args[0])
		if r, ok := st.forwardingRules[id]; ok {
			return &driverMemoryRows{
				columns: []string{"id", "app_id", "prefix", "upstreams", "strip_prefix", "host_header_override", "comment", "is_active", "created_at", "updated_at"},
				data: [][]driver.Value{
					{r.ID, r.AppID, r.Prefix, r.Upstreams, r.StripPrefix, r.HostHeaderOverride, r.Comment, r.IsActive, r.CreatedAt, r.UpdatedAt},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_forwarding_rules") {
		appFilter := ""
		if strings.Contains(q, "WHERE app_id = ?") {
			appFilter = toStringVal(args[0])
		}
		activeOnly := strings.Contains(q, "is_active = 1")
		list := make([]*RaiwallForwardingRule, 0)
		for _, r := range st.forwardingRules {
			if appFilter != "" && r.AppID != appFilter {
				continue
			}
			if activeOnly && r.IsActive != 1 {
				continue
			}
			list = append(list, r)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Prefix < list[j].Prefix
		})
		rows := make([][]driver.Value, len(list))
		for i, r := range list {
			rows[i] = []driver.Value{r.ID, r.AppID, r.Prefix, r.Upstreams, r.StripPrefix, r.HostHeaderOverride, r.Comment, r.IsActive, r.CreatedAt, r.UpdatedAt}
		}
		return &driverMemoryRows{
			columns: []string{"id", "app_id", "prefix", "upstreams", "strip_prefix", "host_header_override", "comment", "is_active", "created_at", "updated_at"},
			data:    rows,
		}, true
	}

	// raiwall_api_resources
	if strings.Contains(q, "FROM raiwall_api_resources WHERE id = ?") {
		id := toStringVal(args[0])
		if r, ok := st.apiResources[id]; ok {
			return &driverMemoryRows{
				columns: []string{"id", "app_id", "method", "path_pattern", "content_type", "hit_count", "last_seen", "created_at"},
				data: [][]driver.Value{
					{r.ID, r.AppID, r.Method, r.PathPattern, r.ContentType, r.HitCount, r.LastSeen, r.CreatedAt},
				},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_api_resources WHERE app_id = ?") {
		appID := toStringVal(args[0])
		list := make([]*RaiwallApiResource, 0)
		for _, r := range st.apiResources {
			if r.AppID == appID {
				list = append(list, r)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].HitCount != list[j].HitCount {
				return list[i].HitCount > list[j].HitCount
			}
			return list[i].LastSeen.After(list[j].LastSeen)
		})
		rows := make([][]driver.Value, len(list))
		for i, r := range list {
			rows[i] = []driver.Value{r.ID, r.AppID, r.Method, r.PathPattern, r.ContentType, r.HitCount, r.LastSeen, r.CreatedAt}
		}
		return &driverMemoryRows{
			columns: []string{"id", "app_id", "method", "path_pattern", "content_type", "hit_count", "last_seen", "created_at"},
			data:    rows,
		}, true
	}

	return nil, false
}
