package caddy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	caddymod "github.com/caddyserver/caddy/v2"
)

func (m *Middleware) provisionStorage(_ caddymod.Context) error {
	if m.storageRegistry != nil {
		return nil
	}

	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	hasCustomStores := m.StorageConfig != nil && len(m.StorageConfig.Stores) > 0

	if !hasCustomStores && dbURL == "" {
		return nil
	}

	regCfg := storage.StorageConfig{
		Stores: make(map[string]storage.StoreConfig),
	}
	if m.StorageConfig != nil {
		regCfg.Control = m.StorageConfig.Control
		regCfg.Telemetry = m.StorageConfig.Telemetry
	}

	retention := 30 * 24 * time.Hour
	if m.TelemetryConfig != nil && m.TelemetryConfig.Retention > 0 {
		retention = time.Duration(m.TelemetryConfig.Retention)
	}

	if hasCustomStores {
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
	} else if dbURL != "" {
		driver := storage.AutoDetectDriver(dbURL)
		regCfg.Stores["default"] = storage.StoreConfig{
			Driver:        driver,
			DSN:           dbURL,
			MaxOpen:       10,
			MaxIdle:       5,
			Retention:     retention,
			PruneInterval: 1 * time.Hour,
		}
		if regCfg.Control == "" {
			regCfg.Control = "default"
		}
		if regCfg.Telemetry == "" {
			regCfg.Telemetry = "default"
		}
	}

	reg, err := storage.NewRegistry(regCfg)
	if err != nil {
		return fmt.Errorf("provision storage registry: %w", err)
	}
	m.storageRegistry = reg
	return nil
}
