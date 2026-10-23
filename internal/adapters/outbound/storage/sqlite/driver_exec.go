package sqlite

import (
	"database/sql/driver"
	"strings"
	"time"
)

func (s *controlStmt) Exec(args []driver.Value) (driver.Result, error) {
	st := s.getTargetState()
	st.mu.Lock()
	defer st.mu.Unlock()

	q := strings.TrimSpace(s.query)
	upper := strings.ToUpper(q)

	if strings.HasPrefix(upper, "PRAGMA") ||
		strings.HasPrefix(upper, "CREATE TABLE") ||
		strings.HasPrefix(upper, "CREATE INDEX") {
		return driver.RowsAffected(0), nil
	}

	if res, handled := s.execCore(st, q, args); handled {
		return res, nil
	}
	if res, handled := s.execMore(st, q, args); handled {
		return res, nil
	}
	if res, handled := s.execPhase7(st, q, args); handled {
		return res, nil
	}
	if res, handled := s.execMatrix(st, q, args); handled {
		return res, nil
	}
	if res, handled := s.execInnerRules(st, q, args); handled {
		return res, nil
	}
	if res, handled := s.execIdentity(st, q, args); handled {
		return res, nil
	}

	return driver.RowsAffected(0), nil
}

func (s *controlStmt) execCore(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	// 1. raiwall_apps
	if strings.Contains(q, "INSERT INTO raiwall_apps") {
		app := &RaiwallApp{
			ID:                  toStringVal(args[0]),
			Name:                toStringVal(args[1]),
			Hostnames:           toStringVal(args[2]),
			Mode:                toStringVal(args[3]),
			Upstreams:           toStringVal(args[4]),
			BlockStatusCode:     toInt64Val(args[5]),
			BlockResponseBody:   toStringVal(args[6]),
			OfflineStatusCode:   toInt64Val(args[7]),
			OfflineResponseBody: toStringVal(args[8]),
			CustomHeaders:       toStringVal(args[9]),
			ProxySettings:       toStringVal(args[10]),
			CreatedAt:           toTime(args[11]),
			UpdatedAt:           toTime(args[12]),
		}
		st.apps[app.ID] = app
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_apps SET") {
		id := toStringVal(args[11])
		if app, ok := st.apps[id]; ok {
			app.Name = toStringVal(args[0])
			app.Hostnames = toStringVal(args[1])
			app.Mode = toStringVal(args[2])
			app.Upstreams = toStringVal(args[3])
			app.BlockStatusCode = toInt64Val(args[4])
			app.BlockResponseBody = toStringVal(args[5])
			app.OfflineStatusCode = toInt64Val(args[6])
			app.OfflineResponseBody = toStringVal(args[7])
			app.CustomHeaders = toStringVal(args[8])
			app.ProxySettings = toStringVal(args[9])
			app.UpdatedAt = toTime(args[10])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_apps") {
		id := toStringVal(args[0])
		if _, ok := st.apps[id]; ok {
			delete(st.apps, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 2. raiwall_exceptions
	if strings.Contains(q, "INSERT INTO raiwall_exceptions") {
		exc := &RaiwallException{
			ID:          toStringVal(args[0]),
			Description: toStringVal(args[1]),
			Host:        toStringVal(args[2]),
			PathRegex:   toStringVal(args[3]),
			PathPrefix:  toStringVal(args[4]),
			Method:      toStringVal(args[5]),
			Location:    toStringVal(args[6]),
			ParamName:   toStringVal(args[7]),
			ParamRegex:  toStringVal(args[8]),
			RuleID:      toStringVal(args[9]),
			IsActive:    toInt64Val(args[10]),
			CreatedAt:   toTime(args[11]),
			UpdatedAt:   toTime(args[12]),
		}
		st.exceptions[exc.ID] = exc
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_exceptions SET") {
		id := toStringVal(args[10])
		if exc, ok := st.exceptions[id]; ok {
			exc.Description = toStringVal(args[0])
			exc.Host = toStringVal(args[1])
			exc.PathRegex = toStringVal(args[2])
			exc.PathPrefix = toStringVal(args[3])
			exc.Method = toStringVal(args[4])
			exc.Location = toStringVal(args[5])
			exc.ParamName = toStringVal(args[6])
			exc.ParamRegex = toStringVal(args[7])
			exc.RuleID = toStringVal(args[8])
			exc.IsActive = toInt64Val(args[9])
			if len(args) > 11 {
				exc.UpdatedAt = toTime(args[10])
				id = toStringVal(args[11])
			} else {
				exc.UpdatedAt = time.Now().UTC()
			}
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_exceptions") {
		id := toStringVal(args[0])
		if _, ok := st.exceptions[id]; ok {
			delete(st.exceptions, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 3. raiwall_acl_rules
	if strings.Contains(q, "INSERT INTO raiwall_acl_rules") {
		rule := &RaiwallAclRule{
			ID:          toStringVal(args[0]),
			Name:        toStringVal(args[1]),
			Expression:  toStringVal(args[2]),
			Action:      toStringVal(args[3]),
			Priority:    toInt64Val(args[4]),
			StatusCode:  toInt64Val(args[5]),
			RedirectUrl: toStringVal(args[6]),
			IsActive:    toInt64Val(args[7]),
			CreatedAt:   toTime(args[8]),
			UpdatedAt:   toTime(args[9]),
		}
		st.aclRules[rule.ID] = rule
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_acl_rules SET") {
		id := toStringVal(args[8])
		if rule, ok := st.aclRules[id]; ok {
			rule.Name = toStringVal(args[0])
			rule.Expression = toStringVal(args[1])
			rule.Action = toStringVal(args[2])
			rule.Priority = toInt64Val(args[3])
			rule.StatusCode = toInt64Val(args[4])
			rule.RedirectUrl = toStringVal(args[5])
			rule.IsActive = toInt64Val(args[6])
			rule.UpdatedAt = toTime(args[7])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_acl_rules") {
		id := toStringVal(args[0])
		if _, ok := st.aclRules[id]; ok {
			delete(st.aclRules, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	// 4. raiwall_rate_policies
	if strings.Contains(q, "INSERT INTO raiwall_rate_policies") {
		pol := &RaiwallRatePolicy{
			ID:                  toStringVal(args[0]),
			Name:                toStringVal(args[1]),
			Host:                toStringVal(args[2]),
			Tier1Rate:           toInt64Val(args[3]),
			Tier1Burst:          toInt64Val(args[4]),
			Tier1PeriodSec:      toInt64Val(args[5]),
			Tier2Threshold:      toInt64Val(args[6]),
			Tier2PeriodSec:      toInt64Val(args[7]),
			Tier2BanDurationSec: toInt64Val(args[8]),
			Tier3Threshold:      toInt64Val(args[9]),
			Tier3BanDurationSec: toInt64Val(args[10]),
			WaitingRoomEnabled:  toInt64Val(args[11]),
			WaitingRoomCapacity: toInt64Val(args[12]),
			WaitingRoomPaths:    toStringVal(args[13]),
			IsActive:            toInt64Val(args[14]),
			CreatedAt:           toTime(args[15]),
			UpdatedAt:           toTime(args[16]),
		}
		st.ratePolicies[pol.ID] = pol
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_rate_policies SET") {
		id := toStringVal(args[15])
		if pol, ok := st.ratePolicies[id]; ok {
			pol.Name = toStringVal(args[0])
			pol.Host = toStringVal(args[1])
			pol.Tier1Rate = toInt64Val(args[2])
			pol.Tier1Burst = toInt64Val(args[3])
			pol.Tier1PeriodSec = toInt64Val(args[4])
			pol.Tier2Threshold = toInt64Val(args[5])
			pol.Tier2PeriodSec = toInt64Val(args[6])
			pol.Tier2BanDurationSec = toInt64Val(args[7])
			pol.Tier3Threshold = toInt64Val(args[8])
			pol.Tier3BanDurationSec = toInt64Val(args[9])
			pol.WaitingRoomEnabled = toInt64Val(args[10])
			pol.WaitingRoomCapacity = toInt64Val(args[11])
			pol.WaitingRoomPaths = toStringVal(args[12])
			pol.IsActive = toInt64Val(args[13])
			pol.UpdatedAt = toTime(args[14])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_rate_policies") {
		id := toStringVal(args[0])
		if _, ok := st.ratePolicies[id]; ok {
			delete(st.ratePolicies, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}

	return nil, false
}
