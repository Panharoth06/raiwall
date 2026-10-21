package sqlite

import (
	"database/sql"
	"database/sql/driver"
	"strings"
)

func (s *controlStmt) execMore(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	// 5. raiwall_bot_configs
	if strings.Contains(q, "INSERT INTO raiwall_bot_configs") {
		cfg := &RaiwallBotConfig{
			ID:            toStringVal(args[0]),
			Host:          toStringVal(args[1]),
			PowEnabled:    toInt64Val(args[2]),
			PowDifficulty: toInt64Val(args[3]),
			TrapUrls:      toStringVal(args[4]),
			IsActive:      toInt64Val(args[5]),
			CreatedAt:     toTime(args[6]),
			UpdatedAt:     toTime(args[7]),
		}
		st.botConfigs[cfg.ID] = cfg
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_bot_configs SET") {
		id := toStringVal(args[6])
		if cfg, ok := st.botConfigs[id]; ok {
			cfg.Host = toStringVal(args[0])
			cfg.PowEnabled = toInt64Val(args[1])
			cfg.PowDifficulty = toInt64Val(args[2])
			cfg.TrapUrls = toStringVal(args[3])
			cfg.IsActive = toInt64Val(args[4])
			cfg.UpdatedAt = toTime(args[5])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_bot_configs") {
		id := toStringVal(args[0])
		if _, ok := st.botConfigs[id]; ok {
			delete(st.botConfigs, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 7. raiwall_users
	if strings.Contains(q, "INSERT INTO raiwall_users") {
		user := &RaiwallUser{
			ID:           toStringVal(args[0]),
			Username:     toStringVal(args[1]),
			PasswordHash: toStringVal(args[2]),
			Role:         toStringVal(args[3]),
			IsActive:     toInt64Val(args[4]),
			CreatedAt:    toTime(args[5]),
			UpdatedAt:    toTime(args[6]),
		}
		st.users[user.ID] = user
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_users SET") {
		id := toStringVal(args[4])
		if user, ok := st.users[id]; ok {
			user.PasswordHash = toStringVal(args[0])
			user.Role = toStringVal(args[1])
			user.IsActive = toInt64Val(args[2])
			user.UpdatedAt = toTime(args[3])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_users") {
		id := toStringVal(args[0])
		if _, ok := st.users[id]; ok {
			delete(st.users, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 8. raiwall_api_keys
	if strings.Contains(q, "INSERT INTO raiwall_api_keys") {
		key := &RaiwallApiKey{
			ID:        toStringVal(args[0]),
			Name:      toStringVal(args[1]),
			KeyHash:   toStringVal(args[2]),
			Role:      toStringVal(args[3]),
			IsActive:  toInt64Val(args[5]),
			CreatedAt: toTime(args[6]),
		}
		if args[4] != nil {
			key.ExpiresAt = sql.NullTime{Time: toTime(args[4]), Valid: true}
		}
		if args[7] != nil {
			key.LastUsedAt = sql.NullTime{Time: toTime(args[7]), Valid: true}
		}
		st.apiKeys[key.ID] = key
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_api_keys SET last_used_at") {
		id := toStringVal(args[1])
		if key, ok := st.apiKeys[id]; ok {
			key.LastUsedAt = sql.NullTime{Time: toTime(args[0]), Valid: true}
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_api_keys") {
		id := toStringVal(args[0])
		if _, ok := st.apiKeys[id]; ok {
			delete(st.apiKeys, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 9. raiwall_forwarding_rules
	if strings.Contains(q, "INSERT INTO raiwall_forwarding_rules") {
		rule := &RaiwallForwardingRule{
			ID:                 toStringVal(args[0]),
			AppID:              toStringVal(args[1]),
			Prefix:             toStringVal(args[2]),
			Upstreams:          toStringVal(args[3]),
			StripPrefix:        toInt64Val(args[4]),
			HostHeaderOverride: toStringVal(args[5]),
			Comment:            toStringVal(args[6]),
			IsActive:           toInt64Val(args[7]),
			CreatedAt:          toTime(args[8]),
			UpdatedAt:          toTime(args[9]),
		}
		st.forwardingRules[rule.ID] = rule
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_forwarding_rules SET") {
		id := toStringVal(args[7])
		if rule, ok := st.forwardingRules[id]; ok {
			rule.Prefix = toStringVal(args[0])
			rule.Upstreams = toStringVal(args[1])
			rule.StripPrefix = toInt64Val(args[2])
			rule.HostHeaderOverride = toStringVal(args[3])
			rule.Comment = toStringVal(args[4])
			rule.IsActive = toInt64Val(args[5])
			rule.UpdatedAt = toTime(args[6])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_forwarding_rules WHERE app_id = ?") {
		appID := toStringVal(args[0])
		var count int64
		for id, r := range st.forwardingRules {
			if r.AppID == appID {
				delete(st.forwardingRules, id)
				count++
			}
		}
		return driver.RowsAffected(count), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_forwarding_rules WHERE id = ?") {
		id := toStringVal(args[0])
		if _, ok := st.forwardingRules[id]; ok {
			delete(st.forwardingRules, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 10. raiwall_api_resources
	if strings.Contains(q, "INSERT INTO raiwall_api_resources") {
		id := toStringVal(args[0])
		appID := toStringVal(args[1])
		method := toStringVal(args[2])
		pathPattern := toStringVal(args[3])
		contentType := toStringVal(args[4])
		hitCount := toInt64Val(args[5])
		lastSeen := toTime(args[6])
		createdAt := toTime(args[7])

		var existing *RaiwallApiResource
		for _, res := range st.apiResources {
			if res.AppID == appID && res.Method == method && res.PathPattern == pathPattern {
				existing = res
				break
			}
		}
		if existing != nil {
			existing.HitCount += hitCount
			if contentType != "" {
				existing.ContentType = contentType
			}
			existing.LastSeen = lastSeen
		} else {
			st.apiResources[id] = &RaiwallApiResource{
				ID:          id,
				AppID:       appID,
				Method:      method,
				PathPattern: pathPattern,
				ContentType: contentType,
				HitCount:    hitCount,
				LastSeen:    lastSeen,
				CreatedAt:   createdAt,
			}
		}
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_api_resources WHERE app_id = ?") {
		appID := toStringVal(args[0])
		var count int64
		for id, r := range st.apiResources {
			if r.AppID == appID {
				delete(st.apiResources, id)
				count++
			}
		}
		return driver.RowsAffected(count), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_api_resources WHERE id = ?") {
		id := toStringVal(args[0])
		if _, ok := st.apiResources[id]; ok {
			delete(st.apiResources, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	if strings.Contains(q, "INSERT INTO raiwall_schema_migrations") || strings.Contains(q, "INSERT OR REPLACE INTO raiwall_schema_migrations") {
		ver := int(toInt64Val(args[0]))
		appliedAt := toStringVal(args[1])
		st.migrations[ver] = appliedAt
		return driver.RowsAffected(1), true
	}

	return nil, false
}
