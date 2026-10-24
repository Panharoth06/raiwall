package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DBTX abstracts database operations between *sql.DB and *sql.Tx.
type DBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ControlStore implements control.ControlStore backed by PostgreSQL.
type ControlStore struct {
	db     DBTX
	rawDB  *sql.DB
	isTx   bool
	ownsDB bool
}

var _ control.ControlStore = (*ControlStore)(nil)

// NewControlStore creates a new PostgreSQL ControlStore adapter sharing an external pool.
func NewControlStore(db *sql.DB) *ControlStore {
	return &ControlStore{
		db:     db,
		rawDB:  db,
		isTx:   false,
		ownsDB: false,
	}
}

// NewStandaloneControlStore creates a PostgreSQL ControlStore that owns and closes db.
func NewStandaloneControlStore(db *sql.DB) *ControlStore {
	return &ControlStore{
		db:     db,
		rawDB:  db,
		isTx:   false,
		ownsDB: true,
	}
}

// WithTx executes operations within a database transaction.
func (s *ControlStore) WithTx(ctx context.Context, fn func(store control.ControlStore) error) error {
	if s.rawDB == nil {
		return fmt.Errorf("transaction not supported on transactional handle")
	}

	tx, err := s.rawDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres transaction: %w", err)
	}

	txStore := &ControlStore{
		db:     tx,
		rawDB:  s.rawDB,
		isTx:   true,
		ownsDB: false,
	}

	if err := fn(txStore); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres transaction: %w", err)
	}
	return nil
}

// Close releases the underlying database pool if this instance owns the connection pool and is not a transaction.
func (s *ControlStore) Close() error {
	if s.ownsDB && !s.isTx && s.rawDB != nil {
		return s.rawDB.Close()
	}
	return nil
}
