package caddy

import (
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	caddymod "github.com/caddyserver/caddy/v2"
)

// provisionStorage builds the named store registry. All connection details are
// supplied by the declarative config adapter; no environment variables are read
// here so the same binary behaves identically in Compose, Helm, and bare metal.
func (m *Middleware) provisionStorage(_ caddymod.Context) error {
	if m.storageRegistry != nil {
		return nil
	}

	if m.StorageConfig == nil || len(m.StorageConfig.Stores) == 0 {
		return nil
	}

	retention := 30 * 24 * time.Hour
	if m.TelemetryConfig != nil && m.TelemetryConfig.Retention > 0 {
		retention = time.Duration(m.TelemetryConfig.Retention)
	}

	regCfg := storage.StorageConfig{
		Stores:    make(map[string]storage.StoreConfig, len(m.StorageConfig.Stores)),
		Control:   m.StorageConfig.Control,
		Telemetry: m.StorageConfig.Telemetry,
	}

	for name, s := range m.StorageConfig.Stores {
		storeRetention := time.Duration(s.Retention)
		if storeRetention <= 0 {
			storeRetention = retention
		}
		regCfg.Stores[name] = storage.StoreConfig{
			Driver:        s.Driver,
			DSN:           s.DSN,
			MaxOpen:       s.MaxOpen,
			MaxIdle:       s.MaxIdle,
			Retention:     storeRetention,
			PruneInterval: time.Duration(s.PruneInterval),
		}
	}

	reg, err := storage.NewRegistry(regCfg)
	if err != nil {
		return fmt.Errorf("provision storage registry: %w", err)
	}
	m.storageRegistry = reg
	return nil
}
