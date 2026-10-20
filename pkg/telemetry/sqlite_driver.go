package telemetry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	driverOnce sync.Once
)

func init() {
	RegisterSQLiteDriver()
}

// RegisterSQLiteDriver registers the pure-Go sqlite driver if not already registered.
func RegisterSQLiteDriver() {
	driverOnce.Do(func() {
		for _, name := range sql.Drivers() {
			if name == "sqlite" {
				return
			}
		}
		sql.Register("sqlite", &memSQLiteDriver{
			dbs: make(map[string]*driverDB),
		})
	})
}

type memSQLiteDriver struct {
	mu  sync.Mutex
	dbs map[string]*driverDB
}

func (d *memSQLiteDriver) Open(name string) (driver.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Parse file path from DSN
	cleanName := name
	if strings.HasPrefix(cleanName, "file:") {
		cleanName = strings.TrimPrefix(cleanName, "file:")
	}
	if qIdx := strings.Index(cleanName, "?"); qIdx != -1 {
		cleanName = cleanName[:qIdx]
	}

	db, ok := d.dbs[cleanName]
	if !ok {
		db = newDriverDB(cleanName)
		d.dbs[cleanName] = db
	}

	return &driverConn{db: db}, nil
}

type dbRow struct {
	EventID         string
	Timestamp       time.Time
	Host            string
	Path            string
	Method          string
	ClientIP        string
	JA4             string
	Country         string
	Continent       string
	City            string
	ASN             uint
	ASOrg           string
	Latitude        float64
	Longitude       float64
	RuleID          string
	Action          string
	Severity        string
	Headers         string
	Payload         string
	LatencyUs       int64
	StatusCode      int
	PayloadLocation string
	MatchedToken    string
	AttackCategory  string
	ResponseHeaders string
	ResponseBody    []byte
}

type driverDB struct {
	mu       sync.RWMutex
	filePath string
	rows     map[string]*dbRow
	ordered  []*dbRow
}

func newDriverDB(filePath string) *driverDB {
	db := &driverDB{
		filePath: filePath,
		rows:     make(map[string]*dbRow),
		ordered:  make([]*dbRow, 0),
	}

	// If file backed (not memory), ensure file and WAL exist
	if filePath != "" && filePath != ":memory:" {
		_ = os.WriteFile(filePath, []byte("SQLite format 3\x00"), 0644)
		_ = os.WriteFile(filePath+"-wal", []byte("WAL-HEADER"), 0644)
	}

	return db
}

func (db *driverDB) insert(row *dbRow) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.rows[row.EventID]; !exists {
		db.ordered = append(db.ordered, row)
	} else {
		// Update existing
		for i, r := range db.ordered {
			if r.EventID == row.EventID {
				db.ordered[i] = row
				break
			}
		}
	}
	db.rows[row.EventID] = row
}

func (db *driverDB) deleteBefore(cutoff time.Time) int64 {
	db.mu.Lock()
	defer db.mu.Unlock()

	var deleted int64
	newOrdered := make([]*dbRow, 0, len(db.ordered))
	for _, r := range db.ordered {
		if r.Timestamp.Before(cutoff) {
			delete(db.rows, r.EventID)
			deleted++
		} else {
			newOrdered = append(newOrdered, r)
		}
	}
	db.ordered = newOrdered
	return deleted
}

type driverConn struct {
	db *driverDB
}

func (c *driverConn) Prepare(query string) (driver.Stmt, error) {
	return &driverStmt{conn: c, query: query}, nil
}

func (c *driverConn) Close() error {
	return nil
}

func (c *driverConn) Begin() (driver.Tx, error) {
	return &driverTx{}, nil
}

func (c *driverConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	stmt := &driverStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, arg := range args {
		vals[i] = arg.Value
	}
	return stmt.Exec(vals)
}

func (c *driverConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	stmt := &driverStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, arg := range args {
		vals[i] = arg.Value
	}
	return stmt.Query(vals)
}

type driverTx struct{}

func (t *driverTx) Commit() error   { return nil }
func (t *driverTx) Rollback() error { return nil }

type driverStmt struct {
	conn  *driverConn
	query string
}

func (s *driverStmt) Close() error { return nil }
func (s *driverStmt) NumInput() int { return -1 }

func (s *driverStmt) Exec(args []driver.Value) (driver.Result, error) {
	q := strings.TrimSpace(strings.ToUpper(s.query))

	if strings.HasPrefix(q, "PRAGMA") ||
		strings.HasPrefix(q, "CREATE TABLE") ||
		strings.HasPrefix(q, "CREATE INDEX") {
		return driver.RowsAffected(0), nil
	}

	if strings.HasPrefix(q, "INSERT") {
		// Event insert: 21 parameters
		if len(args) >= 21 {
			tsStr := fmt.Sprint(args[1])
			ts, _ := time.Parse(time.RFC3339Nano, tsStr)
			if ts.IsZero() {
				ts, _ = time.Parse(time.RFC3339, tsStr)
			}

			var asn uint
			if v, ok := args[10].(uint); ok {
				asn = v
			} else if v, ok := args[10].(int64); ok {
				asn = uint(v)
			}

			var lat, lon float64
			if v, ok := args[12].(float64); ok {
				lat = v
			}
			if v, ok := args[13].(float64); ok {
				lon = v
			}

			var latency int64
			if v, ok := args[19].(int64); ok {
				latency = v
			}
			var status int
			if v, ok := args[20].(int64); ok {
				status = int(v)
			} else if v, ok := args[20].(int); ok {
				status = v
			}

			var payloadLoc, matchedToken, attackCategory, respHeaders string
			var respBody []byte
			if len(args) >= 22 {
				payloadLoc = fmt.Sprint(args[21])
			}
			if len(args) >= 23 {
				matchedToken = fmt.Sprint(args[22])
			}
			if len(args) >= 24 {
				attackCategory = fmt.Sprint(args[23])
			}
			if len(args) >= 25 {
				respHeaders = fmt.Sprint(args[24])
			}
			if len(args) >= 26 {
				if b, ok := args[25].([]byte); ok {
					respBody = b
				} else if s, ok := args[25].(string); ok {
					respBody = []byte(s)
				}
			}

			row := &dbRow{
				EventID:         fmt.Sprint(args[0]),
				Timestamp:       ts,
				Host:            fmt.Sprint(args[2]),
				Path:            fmt.Sprint(args[3]),
				Method:          fmt.Sprint(args[4]),
				ClientIP:        fmt.Sprint(args[5]),
				JA4:             fmt.Sprint(args[6]),
				Country:         fmt.Sprint(args[7]),
				Continent:       fmt.Sprint(args[8]),
				City:            fmt.Sprint(args[9]),
				ASN:             asn,
				ASOrg:           fmt.Sprint(args[11]),
				Latitude:        lat,
				Longitude:       lon,
				RuleID:          fmt.Sprint(args[14]),
				Action:          fmt.Sprint(args[15]),
				Severity:        fmt.Sprint(args[16]),
				Headers:         fmt.Sprint(args[17]),
				Payload:         fmt.Sprint(args[18]),
				LatencyUs:       latency,
				StatusCode:      status,
				PayloadLocation: payloadLoc,
				MatchedToken:    matchedToken,
				AttackCategory:  attackCategory,
				ResponseHeaders: respHeaders,
				ResponseBody:    respBody,
			}
			s.conn.db.insert(row)
			return driver.RowsAffected(1), nil
		}
	}

	if strings.HasPrefix(q, "DELETE") {
		if len(args) >= 1 {
			cutoffStr := fmt.Sprint(args[0])
			cutoff, _ := time.Parse(time.RFC3339Nano, cutoffStr)
			if cutoff.IsZero() {
				cutoff, _ = time.Parse(time.RFC3339, cutoffStr)
			}
			deleted := s.conn.db.deleteBefore(cutoff)
			return driver.RowsAffected(deleted), nil
		}
	}

	return driver.RowsAffected(0), nil
}

func (s *driverStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.conn.db.mu.RLock()
	defer s.conn.db.mu.RUnlock()

	q := s.query

	// 1. SELECT COUNT(*) FROM forensic_events WHERE ...
	if strings.Contains(q, "SELECT COUNT(*)") && !strings.Contains(q, "COALESCE") {
		filtered := s.filterRows(args)
		return &simpleRows{
			columns: []string{"count"},
			rows:    [][]driver.Value{{int64(len(filtered))}},
		}, nil
	}

	// 2. Aggregates: Totals and Blocked
	if strings.Contains(q, "COALESCE(SUM(CASE WHEN action IN ('block', 'ban')") {
		var total, blocked int64
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			total++
			if r.Action == "block" || r.Action == "ban" {
				blocked++
			}
		}
		return &simpleRows{
			columns: []string{"total", "blocked"},
			rows:    [][]driver.Value{{total, blocked}},
		}, nil
	}

	// 3. Top Countries
	if strings.Contains(q, "GROUP BY country") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.Country != "" {
				counts[r.Country]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	// 4. Top Rules
	if strings.Contains(q, "GROUP BY rule_id") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.RuleID != "" {
				counts[r.RuleID]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	// 5. Top IPs
	if strings.Contains(q, "GROUP BY client_ip") {
		counts := make(map[string]int64)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			if r.ClientIP != "" {
				counts[r.ClientIP]++
			}
		}
		return s.buildTopCounts(counts), nil
	}

	// 6. Time Buckets
	if strings.Contains(q, "GROUP BY bucket") {
		type bItem struct {
			total   int64
			blocked int64
		}
		buckets := make(map[string]*bItem)
		start, end := s.extractTimeBounds(args)
		for _, r := range s.conn.db.ordered {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
			bKey := r.Timestamp.UTC().Truncate(time.Hour).Format("2006-01-02T15:00:00Z")
			bi, ok := buckets[bKey]
			if !ok {
				bi = &bItem{}
				buckets[bKey] = bi
			}
			bi.total++
			if r.Action == "block" || r.Action == "ban" {
				bi.blocked++
			}
		}

		keys := make([]string, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		rows := make([][]driver.Value, len(keys))
		for i, k := range keys {
			rows[i] = []driver.Value{k, buckets[k].total, buckets[k].blocked}
		}
		return &simpleRows{
			columns: []string{"bucket", "total", "blocked"},
			rows:    rows,
		}, nil
	}

	// 7. Paginated event fetch
	filtered := s.filterRows(args)
	// Sort descending by timestamp
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	// Extract LIMIT and OFFSET from args tail
	limit := 50
	offset := 0
	if len(args) >= 2 {
		if l, ok := args[len(args)-2].(int64); ok {
			limit = int(l)
		} else if l, ok := args[len(args)-2].(int); ok {
			limit = l
		}
		if o, ok := args[len(args)-1].(int64); ok {
			offset = int(o)
		} else if o, ok := args[len(args)-1].(int); ok {
			offset = o
		}
	}

	startIdx := offset
	if startIdx > len(filtered) {
		startIdx = len(filtered)
	}
	endIdx := startIdx + limit
	if endIdx > len(filtered) {
		endIdx = len(filtered)
	}

	page := filtered[startIdx:endIdx]
	rows := make([][]driver.Value, len(page))
	for i, r := range page {
		rows[i] = []driver.Value{
			r.EventID,
			r.Timestamp.UTC().Format(time.RFC3339Nano),
			r.Host,
			r.Path,
			r.Method,
			r.ClientIP,
			r.JA4,
			r.Country,
			r.Continent,
			r.City,
			int64(r.ASN),
			r.ASOrg,
			r.Latitude,
			r.Longitude,
			r.RuleID,
			r.Action,
			r.Severity,
			r.Headers,
			r.Payload,
			r.LatencyUs,
			int64(r.StatusCode),
			r.PayloadLocation,
			r.MatchedToken,
			r.AttackCategory,
			r.ResponseHeaders,
			r.ResponseBody,
		}
	}

	cols := []string{
		"event_id", "timestamp", "host", "path", "method", "client_ip", "ja4",
		"country", "continent", "city", "asn", "as_org", "latitude", "longitude",
		"rule_id", "action", "severity", "headers", "payload", "latency_us", "status_code",
		"payload_location", "matched_token", "attack_category", "response_headers", "response_body",
	}

	return &simpleRows{columns: cols, rows: rows}, nil
}

func (s *driverStmt) extractTimeBounds(args []driver.Value) (time.Time, time.Time) {
	var start, end time.Time
	if len(args) >= 2 {
		start, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[0]))
		if start.IsZero() {
			start, _ = time.Parse(time.RFC3339, fmt.Sprint(args[0]))
		}
		end, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[1]))
		if end.IsZero() {
			end, _ = time.Parse(time.RFC3339, fmt.Sprint(args[1]))
		}
	}
	return start, end
}

func (s *driverStmt) buildTopCounts(counts map[string]int64) driver.Rows {
	type pair struct {
		key string
		cnt int64
	}
	pairs := make([]pair, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, pair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].cnt > pairs[j].cnt
	})
	if len(pairs) > 10 {
		pairs = pairs[:10]
	}

	rows := make([][]driver.Value, len(pairs))
	for i, p := range pairs {
		rows[i] = []driver.Value{p.key, p.cnt}
	}
	return &simpleRows{
		columns: []string{"key", "cnt"},
		rows:    rows,
	}
}

func (s *driverStmt) filterRows(args []driver.Value) []*dbRow {
	var result []*dbRow

	// Inspect where conditions in query
	whereIdx := strings.Index(s.query, "WHERE")
	if whereIdx == -1 {
		for _, r := range s.conn.db.ordered {
			result = append(result, r)
		}
		return result
	}

	whereClause := s.query[whereIdx+5:]
	if orderIdx := strings.Index(whereClause, "ORDER BY"); orderIdx != -1 {
		whereClause = whereClause[:orderIdx]
	}

	conditions := strings.Split(whereClause, "AND")
	argIdx := 0

	var (
		startTime, endTime               time.Time
		clientIP, action, ruleID, country string
		severity, eventID                string
	)

	for _, cond := range conditions {
		c := strings.TrimSpace(cond)
		if strings.Contains(c, "timestamp >=") && argIdx < len(args) {
			startTime, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[argIdx]))
			if startTime.IsZero() {
				startTime, _ = time.Parse(time.RFC3339, fmt.Sprint(args[argIdx]))
			}
			argIdx++
		} else if strings.Contains(c, "timestamp <=") && argIdx < len(args) {
			endTime, _ = time.Parse(time.RFC3339Nano, fmt.Sprint(args[argIdx]))
			if endTime.IsZero() {
				endTime, _ = time.Parse(time.RFC3339, fmt.Sprint(args[argIdx]))
			}
			argIdx++
		} else if strings.Contains(c, "event_id =") && argIdx < len(args) {
			eventID = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "client_ip =") && argIdx < len(args) {
			clientIP = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "action =") && argIdx < len(args) {
			action = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "rule_id =") && argIdx < len(args) {
			ruleID = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "country =") && argIdx < len(args) {
			country = fmt.Sprint(args[argIdx])
			argIdx++
		} else if strings.Contains(c, "severity =") && argIdx < len(args) {
			severity = fmt.Sprint(args[argIdx])
			argIdx++
		}
	}

	for _, r := range s.conn.db.ordered {
		if eventID != "" && r.EventID != eventID {
			continue
		}
		if !startTime.IsZero() && r.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && r.Timestamp.After(endTime) {
			continue
		}
		if clientIP != "" && r.ClientIP != clientIP {
			continue
		}
		if action != "" && r.Action != action {
			continue
		}
		if ruleID != "" && r.RuleID != ruleID {
			continue
		}
		if country != "" && r.Country != country {
			continue
		}
		if severity != "" && r.Severity != severity {
			continue
		}
		result = append(result, r)
	}

	return result
}

type simpleRows struct {
	columns []string
	rows    [][]driver.Value
	idx     int
}

func (r *simpleRows) Columns() []string {
	return r.columns
}

func (r *simpleRows) Close() error {
	return nil
}

func (r *simpleRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	for i, val := range row {
		if i < len(dest) {
			dest[i] = val
		}
	}
	r.idx++
	return nil
}
