package caddy

import (
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	caddymod "github.com/caddyserver/caddy/v2"
)

func (m *Middleware) provisionStorage(_ caddymod.Context) error {
	if m.storageRegistry != nil || m.StorageConfig == nil || len(m.StorageConfig.Stores) == 0 {
		return nil
	}

	regCfg := storage.StorageConfig{
		Stores:    make(map[string]storage.StoreConfig),
		Control:   m.StorageConfig.Control,
		Telemetry: m.StorageConfig.Telemetry,
	}

	retention := 30 * 24 * time.Hour
	if m.TelemetryConfig != nil && m.TelemetryConfig.Retention > 0 {
		retention = time.Duration(m.TelemetryConfig.Retention)
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
