package storage

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

type standaloneControlStore struct {
	control.ControlStore
	reg *Registry
}

func (s *standaloneControlStore) Close() error {
	_ = s.ControlStore.Close()
	return s.reg.Close()
}

// OpenControlStore is a convenience helper for opening a standalone ControlStore.
func OpenControlStore(ctx context.Context, driver, dsn string) (control.ControlStore, error) {
	if driver == "" {
		driver = AutoDetectDriver(dsn)
	}
	reg, err := NewRegistry(StorageConfig{
		Stores: map[string]StoreConfig{
			"default": {
				Driver: driver,
				DSN:    dsn,
			},
		},
		Control: "default",
	})
	if err != nil {
		return nil, err
	}
	cs, err := reg.ControlStore(ctx)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	return &standaloneControlStore{
		ControlStore: cs,
		reg:          reg,
	}, nil
}

type standaloneTelemetryStore struct {
	telemetry.ForensicStore
	reg *Registry
}

func (s *standaloneTelemetryStore) Close() error {
	_ = s.ForensicStore.Close()
	return s.reg.Close()
}

// OpenTelemetryStore is a convenience helper for opening a standalone TelemetryStore.
func OpenTelemetryStore(ctx context.Context, driver, dsn string, retention, pruneInterval time.Duration) (telemetry.ForensicStore, error) {
	if driver == "" {
		driver = AutoDetectDriver(dsn)
	}
	reg, err := NewRegistry(StorageConfig{
		Stores: map[string]StoreConfig{
			"default": {
				Driver:        driver,
				DSN:           dsn,
				Retention:     retention,
				PruneInterval: pruneInterval,
			},
		},
		Telemetry: "default",
	})
	if err != nil {
		return nil, err
	}
	ts, err := reg.TelemetryStore(ctx)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	return &standaloneTelemetryStore{
		ForensicStore: ts,
		reg:           reg,
	}, nil
}
