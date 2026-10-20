package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
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
