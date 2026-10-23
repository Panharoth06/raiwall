package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

// Identity directory (end-user accounts) and external IdP connector rows.

var identityUserCols = []string{
	"id", "username", "password_hash", "email", "display_name",
	"totp_secret", "totp_enabled", "app_ids", "enabled", "created_at", "updated_at",
}

var identityProviderCols = []string{"id", "type", "name", "config", "enabled", "created_at", "updated_at"}

func identityUserRow(u *RaiwallIdentityUser) []driver.Value {
	return []driver.Value{u.ID, u.Username, u.PasswordHash, u.Email, u.DisplayName,
		u.TOTPSecret, u.TOTPEnabled, u.AppIDs, u.Enabled, u.CreatedAt, u.UpdatedAt}
}

func identityProviderRow(p *RaiwallIdentityProvider) []driver.Value {
	return []driver.Value{p.ID, p.Type, p.Name, p.Config, p.Enabled, p.CreatedAt, p.UpdatedAt}
}

func (s *controlStmt) execIdentity(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	if strings.Contains(q, "INSERT INTO raiwall_identity_users") || strings.Contains(q, "REPLACE INTO raiwall_identity_users") {
		u := &RaiwallIdentityUser{
			ID:           toStringVal(args[0]),
			Username:     toStringVal(args[1]),
			PasswordHash: toStringVal(args[2]),
			Email:        toStringVal(args[3]),
			DisplayName:  toStringVal(args[4]),
			TOTPSecret:   toStringVal(args[5]),
			TOTPEnabled:  toInt64Val(args[6]),
			AppIDs:       toStringVal(args[7]),
			Enabled:      toInt64Val(args[8]),
			CreatedAt:    toTime(args[9]),
			UpdatedAt:    toTime(args[10]),
		}
		// Enforce the unique username index by removing stale rows.
		for id, existing := range st.identityUsers {
			if id != u.ID && existing.Username == u.Username {
				delete(st.identityUsers, id)
			}
		}
		st.identityUsers[u.ID] = u
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_identity_users WHERE id = ?") {
		delete(st.identityUsers, toStringVal(args[0]))
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "INSERT INTO raiwall_identity_providers") || strings.Contains(q, "REPLACE INTO raiwall_identity_providers") {
		p := &RaiwallIdentityProvider{
			ID:        toStringVal(args[0]),
			Type:      toStringVal(args[1]),
			Name:      toStringVal(args[2]),
			Config:    toStringVal(args[3]),
			Enabled:   toInt64Val(args[4]),
			CreatedAt: toTime(args[5]),
			UpdatedAt: toTime(args[6]),
		}
		st.identityProviders[p.ID] = p
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_identity_providers WHERE id = ?") {
		delete(st.identityProviders, toStringVal(args[0]))
		return driver.RowsAffected(1), true
	}
	return nil, false
}

func (s *controlStmt) queryIdentity(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	if strings.Contains(q, "FROM raiwall_identity_users") {
		var found *RaiwallIdentityUser
		var matchesAll bool
		switch {
		case strings.Contains(q, "WHERE username = ?"):
			username := toStringVal(args[0])
			for _, u := range st.identityUsers {
				if u.Username == username {
					found = u
					break
				}
			}
		case strings.Contains(q, "WHERE id = ?"):
			if u, ok := st.identityUsers[toStringVal(args[0])]; ok {
				found = u
			}
		default:
			matchesAll = true
		}

		if !matchesAll {
			if found == nil {
				return &driverMemoryRows{columns: identityUserCols, data: nil}, true
			}
			return &driverMemoryRows{columns: identityUserCols, data: [][]driver.Value{identityUserRow(found)}}, true
		}

		ids := make([]string, 0, len(st.identityUsers))
		for id := range st.identityUsers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		data := make([][]driver.Value, 0, len(ids))
		for _, id := range ids {
			data = append(data, identityUserRow(st.identityUsers[id]))
		}
		return &driverMemoryRows{columns: identityUserCols, data: data}, true
	}
	if strings.Contains(q, "FROM raiwall_identity_providers") {
		ids := make([]string, 0, len(st.identityProviders))
		for id := range st.identityProviders {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		data := make([][]driver.Value, 0, len(ids))
		for _, id := range ids {
			data = append(data, identityProviderRow(st.identityProviders[id]))
		}
		return &driverMemoryRows{columns: identityProviderCols, data: data}, true
	}
	return nil, false
}
