package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	controlDriverOnce sync.Once
)

func init() {
	RegisterDriver()
}

// RegisterDriver registers the "control_sqlite" driver.
func RegisterDriver() {
	controlDriverOnce.Do(func() {
		for _, name := range sql.Drivers() {
			if name == "control_sqlite" {
				return
			}
		}
		sql.Register("control_sqlite", &controlDriver{
			databases: make(map[string]*databaseState),
		})
	})
}

type controlDriver struct {
	mu        sync.Mutex
	databases map[string]*databaseState
}

func (d *controlDriver) Open(name string) (driver.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cleanName := name
	if strings.HasPrefix(cleanName, "file:") {
		cleanName = strings.TrimPrefix(cleanName, "file:")
	}
	if idx := strings.Index(cleanName, "?"); idx != -1 {
		cleanName = cleanName[:idx]
	}
	if cleanName == "" {
		cleanName = ":memory:"
	}

	state, ok := d.databases[cleanName]
	if !ok {
		state = newDatabaseState(cleanName)
		d.databases[cleanName] = state
	}

	return &controlConn{state: state}, nil
}

type databaseState struct {
	mu           sync.RWMutex
	name         string
	apps         map[string]*RaiwallApp
	exceptions   map[string]*RaiwallException
	aclRules     map[string]*RaiwallAclRule
	ratePolicies map[string]*RaiwallRatePolicy
	botConfigs   map[string]*RaiwallBotConfig
	snapshots    []*RaiwallConfigSnapshot
	users        map[string]*RaiwallUser
	apiKeys      map[string]*RaiwallApiKey
	nextVersion  int64
}

func newDatabaseState(name string) *databaseState {
	return &databaseState{
		name:         name,
		apps:         make(map[string]*RaiwallApp),
		exceptions:   make(map[string]*RaiwallException),
		aclRules:     make(map[string]*RaiwallAclRule),
		ratePolicies: make(map[string]*RaiwallRatePolicy),
		botConfigs:   make(map[string]*RaiwallBotConfig),
		snapshots:    make([]*RaiwallConfigSnapshot, 0),
		users:        make(map[string]*RaiwallUser),
		apiKeys:      make(map[string]*RaiwallApiKey),
		nextVersion:  1,
	}
}

func (s *databaseState) clone() *databaseState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := newDatabaseState(s.name)
	cp.nextVersion = s.nextVersion

	for k, v := range s.apps {
		val := *v
		cp.apps[k] = &val
	}
	for k, v := range s.exceptions {
		val := *v
		cp.exceptions[k] = &val
	}
	for k, v := range s.aclRules {
		val := *v
		cp.aclRules[k] = &val
	}
	for k, v := range s.ratePolicies {
		val := *v
		cp.ratePolicies[k] = &val
	}
	for k, v := range s.botConfigs {
		val := *v
		cp.botConfigs[k] = &val
	}
	for _, v := range s.snapshots {
		val := *v
		cp.snapshots = append(cp.snapshots, &val)
	}
	for k, v := range s.users {
		val := *v
		cp.users[k] = &val
	}
	for k, v := range s.apiKeys {
		val := *v
		cp.apiKeys[k] = &val
	}
	return cp
}

func (s *databaseState) applyFrom(src *databaseState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	src.mu.Lock()
	defer src.mu.Unlock()

	s.nextVersion = src.nextVersion
	s.apps = src.apps
	s.exceptions = src.exceptions
	s.aclRules = src.aclRules
	s.ratePolicies = src.ratePolicies
	s.botConfigs = src.botConfigs
	s.snapshots = src.snapshots
	s.users = src.users
	s.apiKeys = src.apiKeys
}

type controlConn struct {
	state *databaseState
	tx    *databaseState
}

func (c *controlConn) Prepare(query string) (driver.Stmt, error) {
	return &controlStmt{conn: c, query: query}, nil
}

func (c *controlConn) Close() error {
	return nil
}

func (c *controlConn) Begin() (driver.Tx, error) {
	if c.tx != nil {
		return nil, errors.New("transaction already active")
	}
	c.tx = c.state.clone()
	return &controlTx{conn: c}, nil
}

func (c *controlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	stmt := &controlStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	return stmt.Exec(vals)
}

func (c *controlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	stmt := &controlStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	return stmt.Query(vals)
}

type controlTx struct {
	conn *controlConn
}

func (t *controlTx) Commit() error {
	if t.conn.tx == nil {
		return errors.New("no transaction to commit")
	}
	t.conn.state.applyFrom(t.conn.tx)
	t.conn.tx = nil
	return nil
}

func (t *controlTx) Rollback() error {
	if t.conn.tx == nil {
		return errors.New("no transaction to rollback")
	}
	t.conn.tx = nil
	return nil
}

type controlStmt struct {
	conn  *controlConn
	query string
}

func (s *controlStmt) Close() error {
	return nil
}

func (s *controlStmt) NumInput() int {
	return -1
}

func (s *controlStmt) getTargetState() *databaseState {
	if s.conn.tx != nil {
		return s.conn.tx
	}
	return s.conn.state
}

func toTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		parsed, _ := time.Parse(time.RFC3339Nano, t)
		if parsed.IsZero() {
			parsed, _ = time.Parse(time.RFC3339, t)
		}
		if parsed.IsZero() {
			parsed, _ = time.Parse("2006-01-02 15:04:05", t)
		}
		return parsed
	default:
		return time.Now().UTC()
	}
}

func toInt64Val(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case float64:
		return int64(n)
	case bool:
		if n {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func toStringVal(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

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
			CreatedAt:           toTime(args[10]),
			UpdatedAt:           toTime(args[11]),
		}
		st.apps[app.ID] = app
		return driver.RowsAffected(1), nil
	}
	if strings.Contains(q, "UPDATE raiwall_apps SET") {
		id := toStringVal(args[10])
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
			app.UpdatedAt = toTime(args[9])
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_apps") {
		id := toStringVal(args[0])
		if _, ok := st.apps[id]; ok {
			delete(st.apps, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
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
		return driver.RowsAffected(1), nil
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
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_exceptions") {
		id := toStringVal(args[0])
		if _, ok := st.exceptions[id]; ok {
			delete(st.exceptions, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
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
		return driver.RowsAffected(1), nil
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
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_acl_rules") {
		id := toStringVal(args[0])
		if _, ok := st.aclRules[id]; ok {
			delete(st.aclRules, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
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
			IsActive:            toInt64Val(args[13]),
			CreatedAt:           toTime(args[14]),
			UpdatedAt:           toTime(args[15]),
		}
		st.ratePolicies[pol.ID] = pol
		return driver.RowsAffected(1), nil
	}
	if strings.Contains(q, "UPDATE raiwall_rate_policies SET") {
		id := toStringVal(args[14])
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
			pol.IsActive = toInt64Val(args[12])
			pol.UpdatedAt = toTime(args[13])
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_rate_policies") {
		id := toStringVal(args[0])
		if _, ok := st.ratePolicies[id]; ok {
			delete(st.ratePolicies, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}

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
		return driver.RowsAffected(1), nil
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
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_bot_configs") {
		id := toStringVal(args[0])
		if _, ok := st.botConfigs[id]; ok {
			delete(st.botConfigs, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
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
		return driver.RowsAffected(1), nil
	}
	if strings.Contains(q, "UPDATE raiwall_users SET") {
		id := toStringVal(args[4])
		if user, ok := st.users[id]; ok {
			user.PasswordHash = toStringVal(args[0])
			user.Role = toStringVal(args[1])
			user.IsActive = toInt64Val(args[2])
			user.UpdatedAt = toTime(args[3])
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_users") {
		id := toStringVal(args[0])
		if _, ok := st.users[id]; ok {
			delete(st.users, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
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
		return driver.RowsAffected(1), nil
	}
	if strings.Contains(q, "UPDATE raiwall_api_keys SET last_used_at") {
		id := toStringVal(args[1])
		if key, ok := st.apiKeys[id]; ok {
			key.LastUsedAt = sql.NullTime{Time: toTime(args[0]), Valid: true}
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "DELETE FROM raiwall_api_keys") {
		id := toStringVal(args[0])
		if _, ok := st.apiKeys[id]; ok {
			delete(st.apiKeys, id)
			return driver.RowsAffected(1), nil
		}
		return driver.RowsAffected(0), nil
	}

	return driver.RowsAffected(0), nil
}

func (s *controlStmt) Query(args []driver.Value) (driver.Rows, error) {
	st := s.getTargetState()
	st.mu.Lock()
	defer st.mu.Unlock()

	q := strings.TrimSpace(s.query)

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
		}, nil
	}

	// raiwall_apps
	if strings.Contains(q, "FROM raiwall_apps WHERE id = ?") {
		id := toStringVal(args[0])
		if app, ok := st.apps[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "hostnames", "mode", "upstreams", "block_status_code",
					"block_response_body", "offline_status_code", "offline_response_body",
					"custom_headers", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						app.ID, app.Name, app.Hostnames, app.Mode, app.Upstreams,
						app.BlockStatusCode, app.BlockResponseBody, app.OfflineStatusCode,
						app.OfflineResponseBody, app.CustomHeaders, app.CreatedAt, app.UpdatedAt,
					},
				},
			}, nil
		}
		return &driverMemoryRows{}, nil
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
				app.OfflineResponseBody, app.CustomHeaders, app.CreatedAt, app.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "hostnames", "mode", "upstreams", "block_status_code",
				"block_response_body", "offline_status_code", "offline_response_body",
				"custom_headers", "created_at", "updated_at",
			},
			data: rows,
		}, nil
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
			}, nil
		}
		return &driverMemoryRows{}, nil
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
		}, nil
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
			}, nil
		}
		return &driverMemoryRows{}, nil
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
		}, nil
	}

	// raiwall_rate_policies
	if strings.Contains(q, "FROM raiwall_rate_policies WHERE id = ?") {
		id := toStringVal(args[0])
		if pol, ok := st.ratePolicies[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "name", "host", "tier1_rate", "tier1_burst", "tier1_period_sec",
					"tier2_threshold", "tier2_period_sec", "tier2_ban_duration_sec",
					"tier3_threshold", "tier3_ban_duration_sec", "waiting_room_enabled",
					"waiting_room_capacity", "is_active", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{
						pol.ID, pol.Name, pol.Host, pol.Tier1Rate, pol.Tier1Burst, pol.Tier1PeriodSec,
						pol.Tier2Threshold, pol.Tier2PeriodSec, pol.Tier2BanDurationSec,
						pol.Tier3Threshold, pol.Tier3BanDurationSec, pol.WaitingRoomEnabled,
						pol.WaitingRoomCapacity, pol.IsActive, pol.CreatedAt, pol.UpdatedAt,
					},
				},
			}, nil
		}
		return &driverMemoryRows{}, nil
	}
	if strings.Contains(q, "FROM raiwall_rate_policies") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallRatePolicy, 0)
		for _, p := range st.ratePolicies {
			if activeOnly && p.IsActive != 1 {
				continue
			}
			list = append(list, p)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, p := range list {
			rows[i] = []driver.Value{
				p.ID, p.Name, p.Host, p.Tier1Rate, p.Tier1Burst, p.Tier1PeriodSec,
				p.Tier2Threshold, p.Tier2PeriodSec, p.Tier2BanDurationSec,
				p.Tier3Threshold, p.Tier3BanDurationSec, p.WaitingRoomEnabled,
				p.WaitingRoomCapacity, p.IsActive, p.CreatedAt, p.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "name", "host", "tier1_rate", "tier1_burst", "tier1_period_sec",
				"tier2_threshold", "tier2_period_sec", "tier2_ban_duration_sec",
				"tier3_threshold", "tier3_ban_duration_sec", "waiting_room_enabled",
				"waiting_room_capacity", "is_active", "created_at", "updated_at",
			},
			data: rows,
		}, nil
	}

	// raiwall_bot_configs
	if strings.Contains(q, "FROM raiwall_bot_configs WHERE id = ?") {
		id := toStringVal(args[0])
		if b, ok := st.botConfigs[id]; ok {
			return &driverMemoryRows{
				columns: []string{
					"id", "host", "pow_enabled", "pow_difficulty", "trap_urls",
					"is_active", "created_at", "updated_at",
				},
				data: [][]driver.Value{
					{b.ID, b.Host, b.PowEnabled, b.PowDifficulty, b.TrapUrls, b.IsActive, b.CreatedAt, b.UpdatedAt},
				},
			}, nil
		}
		return &driverMemoryRows{}, nil
	}
	if strings.Contains(q, "FROM raiwall_bot_configs") {
		activeOnly := strings.Contains(q, "WHERE is_active = 1")
		list := make([]*RaiwallBotConfig, 0)
		for _, b := range st.botConfigs {
			if activeOnly && b.IsActive != 1 {
				continue
			}
			list = append(list, b)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		rows := make([][]driver.Value, len(list))
		for i, b := range list {
			rows[i] = []driver.Value{
				b.ID, b.Host, b.PowEnabled, b.PowDifficulty, b.TrapUrls, b.IsActive, b.CreatedAt, b.UpdatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{
				"id", "host", "pow_enabled", "pow_difficulty", "trap_urls",
				"is_active", "created_at", "updated_at",
			},
			data: rows,
		}, nil
	}

	// raiwall_config_snapshots
	if strings.Contains(q, "FROM raiwall_config_snapshots WHERE version = ?") {
		ver := toInt64Val(args[0])
		for _, snap := range st.snapshots {
			if snap.Version == ver {
				return &driverMemoryRows{
					columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
					data: [][]driver.Value{
						{snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt},
					},
				}, nil
			}
		}
		return &driverMemoryRows{}, nil
	}
	if strings.Contains(q, "FROM raiwall_config_snapshots ORDER BY version DESC LIMIT 1") {
		if len(st.snapshots) > 0 {
			snap := st.snapshots[len(st.snapshots)-1]
			return &driverMemoryRows{
				columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
				data: [][]driver.Value{
					{snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt},
				},
			}, nil
		}
		return &driverMemoryRows{}, nil
	}
	if strings.Contains(q, "FROM raiwall_config_snapshots ORDER BY version DESC") {
		list := make([]*RaiwallConfigSnapshot, len(st.snapshots))
		copy(list, st.snapshots)
		sort.Slice(list, func(i, j int) bool {
			return list[i].Version > list[j].Version
		})
		rows := make([][]driver.Value, len(list))
		for i, snap := range list {
			rows[i] = []driver.Value{
				snap.Version, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt,
			}
		}
		return &driverMemoryRows{
			columns: []string{"version", "snapshot_data", "author", "description", "created_at"},
			data: rows,
		}, nil
	}

	// raiwall_users
	if strings.Contains(q, "FROM raiwall_users WHERE id = ?") {
		id := toStringVal(args[0])
		if u, ok := st.users[id]; ok {
			return &driverMemoryRows{
				columns: []string{"id", "username", "password_hash", "role", "is_active", "created_at", "updated_at"},
				data: [][]driver.Value{
					{u.ID, u.Username, u.PasswordHash, u.Role, u.IsActive, u.CreatedAt, u.UpdatedAt},
				},
			}, nil
		}
		return &driverMemoryRows{}, nil
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
				}, nil
			}
		}
		return &driverMemoryRows{}, nil
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
			data: rows,
		}, nil
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
			}, nil
		}
		return &driverMemoryRows{}, nil
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
				}, nil
			}
		}
		return &driverMemoryRows{}, nil
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
		}, nil
	}

	return &driverMemoryRows{}, nil
}

type driverMemoryRows struct {
	columns []string
	data    [][]driver.Value
	idx     int
}

func (r *driverMemoryRows) Columns() []string {
	return r.columns
}

func (r *driverMemoryRows) Close() error {
	return nil
}

func (r *driverMemoryRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	row := r.data[r.idx]
	r.idx++
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		} else {
			dest[i] = nil
		}
	}
	return nil
}
