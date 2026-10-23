package sqlite

import (
	"database/sql/driver"
	"fmt"
	"io"
	"sync"
	"time"
)

type databaseState struct {
	mu                sync.RWMutex
	name              string
	apps              map[string]*RaiwallApp
	exceptions        map[string]*RaiwallException
	aclRules          map[string]*RaiwallAclRule
	ratePolicies      map[string]*RaiwallRatePolicy
	botConfigs        map[string]*RaiwallBotConfig
	snapshots         []*RaiwallConfigSnapshot
	users             map[string]*RaiwallUser
	apiKeys           map[string]*RaiwallApiKey
	forwardingRules   map[string]*RaiwallForwardingRule
	apiResources      map[string]*RaiwallApiResource
	ipGroups          map[string]*RaiwallIPGroup
	ipGroupEntries    map[string]*RaiwallIPGroupEntry
	templates         map[int]*RaiwallResponseTemplate
	detectorConfig    map[string]string
	appSemPolicies    map[string]string
	innerRuleDisabled map[string]time.Time
	migrations        map[int]string
	nextVersion       int64
}

func newDatabaseState(name string) *databaseState {
	return &databaseState{
		name:              name,
		apps:              make(map[string]*RaiwallApp),
		exceptions:        make(map[string]*RaiwallException),
		aclRules:          make(map[string]*RaiwallAclRule),
		ratePolicies:      make(map[string]*RaiwallRatePolicy),
		botConfigs:        make(map[string]*RaiwallBotConfig),
		snapshots:         make([]*RaiwallConfigSnapshot, 0),
		users:             make(map[string]*RaiwallUser),
		apiKeys:           make(map[string]*RaiwallApiKey),
		forwardingRules:   make(map[string]*RaiwallForwardingRule),
		apiResources:      make(map[string]*RaiwallApiResource),
		ipGroups:          make(map[string]*RaiwallIPGroup),
		ipGroupEntries:    make(map[string]*RaiwallIPGroupEntry),
		templates:         make(map[int]*RaiwallResponseTemplate),
		detectorConfig:    make(map[string]string),
		appSemPolicies:    make(map[string]string),
		innerRuleDisabled: make(map[string]time.Time),
		migrations:        make(map[int]string),
		nextVersion:       1,
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
	for k, v := range s.forwardingRules {
		val := *v
		cp.forwardingRules[k] = &val
	}
	for k, v := range s.apiResources {
		val := *v
		cp.apiResources[k] = &val
	}
	for k, v := range s.ipGroups {
		val := *v
		cp.ipGroups[k] = &val
	}
	for k, v := range s.ipGroupEntries {
		val := *v
		cp.ipGroupEntries[k] = &val
	}
	for k, v := range s.templates {
		val := *v
		cp.templates[k] = &val
	}
	for k, v := range s.detectorConfig {
		cp.detectorConfig[k] = v
	}
	for k, v := range s.appSemPolicies {
		cp.appSemPolicies[k] = v
	}
	for k, v := range s.innerRuleDisabled {
		cp.innerRuleDisabled[k] = v
	}
	for k, v := range s.migrations {
		cp.migrations[k] = v
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
	s.forwardingRules = src.forwardingRules
	s.apiResources = src.apiResources
	s.ipGroups = src.ipGroups
	s.ipGroupEntries = src.ipGroupEntries
	s.templates = src.templates
	s.detectorConfig = src.detectorConfig
	s.appSemPolicies = src.appSemPolicies
	s.innerRuleDisabled = src.innerRuleDisabled
	s.migrations = src.migrations
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
