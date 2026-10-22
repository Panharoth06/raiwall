package sqlite

import (
	"database/sql/driver"
	"strings"
)

func (s *controlStmt) execPhase7(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	// 1. raiwall_ip_groups
	if strings.Contains(q, "INSERT INTO raiwall_ip_groups") {
		grp := &RaiwallIPGroup{
			ID:          toStringVal(args[0]),
			Name:        toStringVal(args[1]),
			Description: toStringVal(args[2]),
			Type:        toStringVal(args[3]),
			CreatedAt:   toTime(args[4]),
			UpdatedAt:   toTime(args[5]),
		}
		st.ipGroups[grp.ID] = grp
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_ip_groups SET") {
		id := toStringVal(args[4])
		if grp, ok := st.ipGroups[id]; ok {
			grp.Name = toStringVal(args[0])
			grp.Description = toStringVal(args[1])
			grp.Type = toStringVal(args[2])
			grp.UpdatedAt = toTime(args[3])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_ip_groups WHERE id = ?") {
		id := toStringVal(args[0])
		if grp, ok := st.ipGroups[id]; ok {
			delete(st.ipGroups, grp.ID)
			// cascade delete entries
			for k, e := range st.ipGroupEntries {
				if e.GroupID == id {
					delete(st.ipGroupEntries, k)
				}
			}
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 2. raiwall_ip_group_entries
	if strings.Contains(q, "INSERT INTO raiwall_ip_group_entries") {
		entry := &RaiwallIPGroupEntry{
			ID:        toStringVal(args[0]),
			GroupID:   toStringVal(args[1]),
			CIDROrIP:  toStringVal(args[2]),
			Comment:   toStringVal(args[3]),
			CreatedAt: toTime(args[4]),
		}
		st.ipGroupEntries[entry.ID] = entry
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_ip_group_entries WHERE id = ?") {
		id := toStringVal(args[0])
		if _, ok := st.ipGroupEntries[id]; ok {
			delete(st.ipGroupEntries, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 3. raiwall_response_templates
	if strings.Contains(q, "INSERT INTO raiwall_response_templates") || strings.Contains(q, "REPLACE INTO raiwall_response_templates") {
		tmpl := &RaiwallResponseTemplate{
			ID:          toStringVal(args[0]),
			StatusCode:  int(toInt64Val(args[1])),
			Title:       toStringVal(args[2]),
			ContentHTML: toStringVal(args[3]),
			CustomCSS:   toStringVal(args[4]),
			BrandName:   toStringVal(args[5]),
			LogoURL:     toStringVal(args[6]),
			IsCustom:    toInt64Val(args[7]),
			CreatedAt:   toTime(args[8]),
			UpdatedAt:   toTime(args[9]),
		}
		st.templates[tmpl.StatusCode] = tmpl
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_response_templates SET") {
		statusCode := int(toInt64Val(args[7]))
		if tmpl, ok := st.templates[statusCode]; ok {
			tmpl.Title = toStringVal(args[0])
			tmpl.ContentHTML = toStringVal(args[1])
			tmpl.CustomCSS = toStringVal(args[2])
			tmpl.BrandName = toStringVal(args[3])
			tmpl.LogoURL = toStringVal(args[4])
			tmpl.IsCustom = toInt64Val(args[5])
			tmpl.UpdatedAt = toTime(args[6])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_response_templates WHERE status_code = ?") {
		statusCode := int(toInt64Val(args[0]))
		if _, ok := st.templates[statusCode]; ok {
			delete(st.templates, statusCode)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	return nil, false
}
