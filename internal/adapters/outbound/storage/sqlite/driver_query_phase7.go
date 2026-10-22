package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

func (s *controlStmt) queryPhase7(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	// count(*) queries
	if strings.Contains(strings.ToLower(q), "count(*)") {
		if strings.Contains(q, "FROM raiwall_ip_groups") {
			return &driverMemoryRows{
				columns: []string{"count"},
				data:    [][]driver.Value{{int64(len(st.ipGroups))}},
			}, true
		}
		if strings.Contains(q, "FROM raiwall_response_templates") {
			return &driverMemoryRows{
				columns: []string{"count"},
				data:    [][]driver.Value{{int64(len(st.templates))}},
			}, true
		}
		if strings.Contains(q, "FROM raiwall_ip_group_entries") {
			return &driverMemoryRows{
				columns: []string{"count"},
				data:    [][]driver.Value{{int64(len(st.ipGroupEntries))}},
			}, true
		}
	}

	// 1. raiwall_ip_groups
	if strings.Contains(q, "FROM raiwall_ip_groups WHERE id = ?") {
		id := toStringVal(args[0])
		if grp, ok := st.ipGroups[id]; ok {
			return &driverMemoryRows{
				columns: []string{"id", "name", "description", "type", "created_at", "updated_at"},
				data: [][]driver.Value{
					{grp.ID, grp.Name, grp.Description, grp.Type, grp.CreatedAt, grp.UpdatedAt},
				},
			}, true
		}
		return &driverMemoryRows{
			columns: []string{"id", "name", "description", "type", "created_at", "updated_at"},
			data:    [][]driver.Value{},
		}, true
	}

	if strings.Contains(q, "FROM raiwall_ip_groups WHERE name = ?") {
		name := toStringVal(args[0])
		for _, grp := range st.ipGroups {
			if grp.Name == name {
				return &driverMemoryRows{
					columns: []string{"id", "name", "description", "type", "created_at", "updated_at"},
					data: [][]driver.Value{
						{grp.ID, grp.Name, grp.Description, grp.Type, grp.CreatedAt, grp.UpdatedAt},
					},
				}, true
			}
		}
		return &driverMemoryRows{
			columns: []string{"id", "name", "description", "type", "created_at", "updated_at"},
			data:    [][]driver.Value{},
		}, true
	}

	if strings.Contains(q, "FROM raiwall_ip_groups") && strings.Contains(q, "SELECT") {
		list := make([]*RaiwallIPGroup, 0, len(st.ipGroups))
		for _, g := range st.ipGroups {
			list = append(list, g)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		})
		data := make([][]driver.Value, len(list))
		for i, grp := range list {
			data[i] = []driver.Value{grp.ID, grp.Name, grp.Description, grp.Type, grp.CreatedAt, grp.UpdatedAt}
		}
		return &driverMemoryRows{
			columns: []string{"id", "name", "description", "type", "created_at", "updated_at"},
			data:    data,
		}, true
	}

	// 2. raiwall_ip_group_entries
	if strings.Contains(q, "FROM raiwall_ip_group_entries WHERE group_id = ?") {
		groupID := toStringVal(args[0])
		list := make([]*RaiwallIPGroupEntry, 0)
		for _, e := range st.ipGroupEntries {
			if e.GroupID == groupID {
				list = append(list, e)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		})
		data := make([][]driver.Value, len(list))
		for i, e := range list {
			data[i] = []driver.Value{e.ID, e.GroupID, e.CIDROrIP, e.Comment, e.CreatedAt}
		}
		return &driverMemoryRows{
			columns: []string{"id", "group_id", "cidr_or_ip", "comment", "created_at"},
			data:    data,
		}, true
	}

	// 3. raiwall_response_templates
	if strings.Contains(q, "FROM raiwall_response_templates WHERE status_code = ?") {
		statusCode := int(toInt64Val(args[0]))
		if tmpl, ok := st.templates[statusCode]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "status_code", "title", "content_html", "custom_css",
					"brand_name", "logo_url", "is_custom", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						tmpl.ID, int64(tmpl.StatusCode), tmpl.Title, tmpl.ContentHTML, tmpl.CustomCSS,
						tmpl.BrandName, tmpl.LogoURL, tmpl.IsCustom, tmpl.CreatedAt, tmpl.UpdatedAt,
					},
				},
			}, true
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "status_code", "title", "content_html", "custom_css",
				"brand_name", "logo_url", "is_custom", "created_at", "updated_at",
			},
			data: [][]driver.Value{},
		}, true
	}

	if strings.Contains(q, "FROM raiwall_response_templates") && strings.Contains(q, "SELECT") {
		list := make([]*RaiwallResponseTemplate, 0, len(st.templates))
		for _, t := range st.templates {
			list = append(list, t)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].StatusCode < list[j].StatusCode
		})
		data := make([][]driver.Value, len(list))
		for i, tmpl := range list {
			data[i] = []driver.Value{
				tmpl.ID, int64(tmpl.StatusCode), tmpl.Title, tmpl.ContentHTML, tmpl.CustomCSS,
				tmpl.BrandName, tmpl.LogoURL, tmpl.IsCustom, tmpl.CreatedAt, tmpl.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "status_code", "title", "content_html", "custom_css",
				"brand_name", "logo_url", "is_custom", "created_at", "updated_at",
			},
			data: data,
		}, true
	}

	return nil, false
}
