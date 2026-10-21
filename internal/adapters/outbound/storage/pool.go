package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/migration"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func (r *Registry) getOrOpenPool(ctx context.Context, name string, sc StoreConfig) (*sql.DB, error) {
	r.mu.Lock()
	if pool, ok := r.pools[name]; ok {
		r.mu.Unlock()
		return pool, nil
	}
	r.mu.Unlock()

	driver := migration.NormalizeDriver(sc.Driver)
	if driver == "" {
		driver = AutoDetectDriver(sc.DSN)
	}

	var (
		db  *sql.DB
		err error
	)

	switch driver {
	case "postgres":
		db, err = sql.Open("pgx", sc.DSN)
		if err != nil {
			return nil, fmt.Errorf("open postgres pool: %w", err)
		}
		if sc.MaxOpen > 0 {
			db.SetMaxOpenConns(sc.MaxOpen)
		}
		if sc.MaxIdle > 0 {
			db.SetMaxIdleConns(sc.MaxIdle)
		}

	case "sqlite":
		sqlite.RegisterDriver()
		dsn := sc.DSN
		if dsn == "" {
			dsn = "file:raiwall.db?_pragma=busy_timeout(5000)"
		}
		db, err = sql.Open("control_sqlite", dsn)
		if err != nil {
			return nil, fmt.Errorf("open sqlite pool: %w", err)
		}
		maxOpen := sc.MaxOpen
		if maxOpen <= 0 {
			maxOpen = 1
		}
		maxIdle := sc.MaxIdle
		if maxIdle <= 0 {
			maxIdle = 1
		}
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxIdle)

	default:
		return nil, fmt.Errorf("unsupported database pool driver: %s", driver)
	}

	// Run embedded migrations
	if err := migration.Run(ctx, db, driver); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("run schema migrations for %q: %w", name, err)
	}

	r.mu.Lock()
	r.pools[name] = db
	r.mu.Unlock()

	return db, nil
}
