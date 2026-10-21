package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

//go:embed schema.sql
var schemaSQL string

// Store provides persistence for Raiwall Control Plane entities.
type Store struct {
	db     *sql.DB
	ownsDB bool
	*Queries
}

// InitDB initializes database connection, applies WAL pragmas and executes migrations.
func InitDB(dsn string) (*Store, error) {
	if dsn == "" {
		dsn = "file:raiwall_control.db?_pragma=busy_timeout(5000)"
	}

	RegisterDriver()

	db, err := sql.Open("control_sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Apply pragmas
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Apply schema migrations
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to apply database schema: %w", err)
	}

	return &Store{
		db:      db,
		ownsDB:  true,
		Queries: New(db),
	}, nil
}

// NewFromDB creates a Store wrapping an existing *sql.DB connection pool.
func NewFromDB(db *sql.DB) *Store {
	return &Store{
		db:      db,
		ownsDB:  false,
		Queries: New(db),
	}
}

// DB returns the underlying sql.DB instance.
func (s *Store) DB() *sql.DB {
	return s.db
}

// WithTx executes operations within a database transaction using control.ControlStore.
// If fn returns an error, the transaction is automatically rolled back.
func (s *Store) WithTx(ctx context.Context, fn func(store control.ControlStore) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	txStore := &Store{
		db:      s.db,
		Queries: s.Queries.WithTx(tx),
	}
	if err := fn(txStore); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// WithQueriesTx executes operations within a transaction with direct access to *Queries.
func (s *Store) WithQueriesTx(ctx context.Context, fn func(q *Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	q := s.Queries.WithTx(tx)
	if err := fn(q); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// Close releases the database resources.
func (s *Store) Close() error {
	if s.ownsDB && s.db != nil {
		return s.db.Close()
	}
	return nil
}
