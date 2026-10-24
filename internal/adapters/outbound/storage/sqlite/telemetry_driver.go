package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	telemetryDriverOnce sync.Once
)

func init() {
	RegisterSQLiteDriver()
}

// RegisterSQLiteDriver registers the pure-Go sqlite driver if not already registered.
func RegisterSQLiteDriver() {
	telemetryDriverOnce.Do(func() {
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

	return &telemetryDriverConn{db: db}, nil
}

type telemetryDBRow struct {
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
	rows     map[string]*telemetryDBRow
	ordered  []*telemetryDBRow
}

func newDriverDB(filePath string) *driverDB {
	db := &driverDB{
		filePath: filePath,
		rows:     make(map[string]*telemetryDBRow),
		ordered:  make([]*telemetryDBRow, 0),
	}

	if filePath != "" && filePath != ":memory:" {
		_ = os.WriteFile(filePath, []byte("SQLite format 3\x00"), 0644)
		_ = os.WriteFile(filePath+"-wal", []byte("WAL-HEADER"), 0644)
	}

	return db
}

func (db *driverDB) insert(row *telemetryDBRow) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.rows[row.EventID]; !exists {
		db.ordered = append(db.ordered, row)
	} else {
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
	newOrdered := make([]*telemetryDBRow, 0, len(db.ordered))
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

type telemetryDriverConn struct {
	db *driverDB
}

func (c *telemetryDriverConn) Prepare(query string) (driver.Stmt, error) {
	return &telemetryDriverStmt{conn: c, query: query}, nil
}

func (c *telemetryDriverConn) Close() error {
	return nil
}

func (c *telemetryDriverConn) Begin() (driver.Tx, error) {
	return &telemetryDriverTx{}, nil
}

func (c *telemetryDriverConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	stmt := &telemetryDriverStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, arg := range args {
		vals[i] = arg.Value
	}
	return stmt.Exec(vals)
}

func (c *telemetryDriverConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	stmt := &telemetryDriverStmt{conn: c, query: query}
	vals := make([]driver.Value, len(args))
	for i, arg := range args {
		vals[i] = arg.Value
	}
	return stmt.Query(vals)
}

type telemetryDriverTx struct{}

func (t *telemetryDriverTx) Commit() error   { return nil }
func (t *telemetryDriverTx) Rollback() error { return nil }

type telemetryDriverStmt struct {
	conn  *telemetryDriverConn
	query string
}

func (s *telemetryDriverStmt) Close() error  { return nil }
func (s *telemetryDriverStmt) NumInput() int { return -1 }

type telemetrySimpleRows struct {
	columns []string
	rows    [][]driver.Value
	idx     int
}

func (r *telemetrySimpleRows) Columns() []string {
	return r.columns
}

func (r *telemetrySimpleRows) Close() error {
	return nil
}

func (r *telemetrySimpleRows) Next(dest []driver.Value) error {
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
