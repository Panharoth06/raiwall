package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/clickhouse"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/migration"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/postgres"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// StoreConfig defines connection and lifecycle parameters for a named storage backend.
type StoreConfig struct {
	Driver        string        `json:"driver"`                   // "sqlite", "postgres", "clickhouse"
	DSN           string        `json:"dsn"`                      // Connection string or file path
	MaxOpen       int           `json:"max_open,omitempty"`       // Maximum open connections
	MaxIdle       int           `json:"max_idle,omitempty"`       // Maximum idle connections
	Retention     time.Duration `json:"retention,omitempty"`      // Forensic log retention duration
	PruneInterval time.Duration `json:"prune_interval,omitempty"` // Periodic pruning interval
}

// StorageConfig specifies named storage definitions and operational role bindings.
type StorageConfig struct {
	Stores    map[string]StoreConfig `json:"stores"`    // Named stores map
	Control   string                 `json:"control"`   // Store bound to control role
	Telemetry string                 `json:"telemetry"` // Store bound to telemetry role
}

// Registry manages storage lifecycle, shared connection pools, and role-bound store instances.
type Registry struct {
	mu        sync.Mutex
	cfg       StorageConfig
	pools     map[string]*sql.DB // Shared *sql.DB pools keyed by store name
	control   control.ControlStore
	telemetry telemetry.ForensicStore
}

// NewRegistry initializes a new Storage Registry.
func NewRegistry(cfg StorageConfig) (*Registry, error) {
	if cfg.Stores == nil {
		cfg.Stores = make(map[string]StoreConfig)
	}

	return &Registry{
		cfg:   cfg,
		pools: make(map[string]*sql.DB),
	}, nil
}

// AutoDetectDriver determines the database driver based on DSN prefix or parameters.
func AutoDetectDriver(dsn string) string {
	s := strings.ToLower(strings.TrimSpace(dsn))
	if strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://") {
		return "postgres"
	}
	if strings.Contains(s, "host=") && (strings.Contains(s, "user=") || strings.Contains(s, "dbname=")) {
		return "postgres"
	}
	return "sqlite"
}

// ControlStore resolves and returns the ControlStore instance bound to the control role.
func (r *Registry) ControlStore(ctx context.Context) (control.ControlStore, error) {
	r.mu.Lock()
	if r.control != nil {
		defer r.mu.Unlock()
		return r.control, nil
	}
	r.mu.Unlock()

	storeName := r.cfg.Control
	if storeName == "" {
		if len(r.cfg.Stores) == 1 {
			for k := range r.cfg.Stores {
				storeName = k
				break
			}
		} else {
			storeName = "default"
		}
	}

	sc, ok := r.cfg.Stores[storeName]
	if !ok {
		if storeName == "default" {
			sc = StoreConfig{
				Driver:  "sqlite",
				DSN:     "file:raiwall_control.db?_pragma=busy_timeout(5000)",
				MaxOpen: 1,
				MaxIdle: 1,
			}
			r.cfg.Stores[storeName] = sc
		} else {
			return nil, fmt.Errorf("control role bound to unconfigured store: %q", storeName)
		}
	}

	driver := migration.NormalizeDriver(sc.Driver)
	if driver == "" {
		driver = AutoDetectDriver(sc.DSN)
	}

	pool, err := r.getOrOpenPool(ctx, storeName, sc)
	if err != nil {
		return nil, fmt.Errorf("open pool for control store %q: %w", storeName, err)
	}

	var cs control.ControlStore
	switch driver {
	case "postgres":
		cs = postgres.NewControlStore(pool)
	case "sqlite":
		cs = sqlite.NewFromDB(pool)
	default:
		return nil, fmt.Errorf("unsupported driver %q for control plane store", driver)
	}

	r.mu.Lock()
	r.control = cs
	r.mu.Unlock()

	return cs, nil
}

// TelemetryStore resolves and returns the ForensicStore instance bound to the telemetry role.
func (r *Registry) TelemetryStore(ctx context.Context) (telemetry.ForensicStore, error) {
	r.mu.Lock()
	if r.telemetry != nil {
		defer r.mu.Unlock()
		return r.telemetry, nil
	}
	r.mu.Unlock()

	storeName := r.cfg.Telemetry
	if storeName == "" {
		if len(r.cfg.Stores) == 1 {
			for k := range r.cfg.Stores {
				storeName = k
				break
			}
		} else {
			storeName = "default"
		}
	}

	sc, ok := r.cfg.Stores[storeName]
	if !ok {
		if storeName == "default" {
			sc = StoreConfig{
				Driver:    "sqlite",
				DSN:       "file:raiwall_forensics.db?_pragma=busy_timeout(5000)",
				Retention: 30 * 24 * time.Hour,
			}
			r.cfg.Stores[storeName] = sc
		} else {
			return nil, fmt.Errorf("telemetry role bound to unconfigured store: %q", storeName)
		}
	}

	driver := migration.NormalizeDriver(sc.Driver)
	if driver == "" {
		driver = AutoDetectDriver(sc.DSN)
	}

	if driver == "clickhouse" {
		ch, err := clickhouse.NewClickHouseStore(clickhouse.ClickHouseConfig{URL: sc.DSN})
		if err != nil {
			return nil, fmt.Errorf("open clickhouse telemetry store: %w", err)
		}
		r.mu.Lock()
		r.telemetry = ch
		r.mu.Unlock()
		return ch, nil
	}

	pool, err := r.getOrOpenPool(ctx, storeName, sc)
	if err != nil {
		return nil, fmt.Errorf("open pool for telemetry store %q: %w", storeName, err)
	}

	var ts telemetry.ForensicStore
	switch driver {
	case "postgres":
		ts = postgres.NewTelemetryStore(pool, sc.Retention, sc.PruneInterval)
	case "sqlite":
		sqStore, err := sqlite.NewTelemetryStoreFromDB(pool, sc.Retention, sc.PruneInterval)
		if err != nil {
			return nil, fmt.Errorf("create sqlite telemetry store from pool: %w", err)
		}
		ts = sqStore
	default:
		return nil, fmt.Errorf("unsupported driver %q for telemetry store", driver)
	}

	r.mu.Lock()
	r.telemetry = ts
	r.mu.Unlock()

	return ts, nil
}

// Close gracefully terminates all role-bound stores and underlying shared connection pools.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []string

	if r.telemetry != nil {
		if err := r.telemetry.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("close telemetry store: %v", err))
		}
		r.telemetry = nil
	}

	if r.control != nil {
		if err := r.control.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("close control store: %v", err))
		}
		r.control = nil
	}

	for name, pool := range r.pools {
		if pool != nil {
			if err := pool.Close(); err != nil {
				errs = append(errs, fmt.Sprintf("close pool %q: %v", name, err))
			}
		}
		delete(r.pools, name)
	}

	if len(errs) > 0 {
		return fmt.Errorf("storage registry close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

