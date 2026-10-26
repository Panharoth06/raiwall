package caddy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/alerts"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/clickhouse"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func (m *Middleware) provisionTelemetry(_ caddy.Context) error {
	if m.uiHandler == nil {
		uiHandler, err := NewUIHandler()
		if err != nil && m.logger != nil {
			m.logger.Warn("Failed to initialize UI handler", zap.Error(err))
		} else {
			m.uiHandler = uiHandler
		}
	}

	if m.metrics == nil {
		m.metrics = telemetry.NewMetrics(nil)
	}
	if m.streamer == nil {
		m.streamer = api.NewEventStreamer()
	}

	if m.telemetryStore == nil {
		if m.storageRegistry != nil {
			if m.TelemetryConfig != nil && strings.TrimSpace(m.TelemetryConfig.StorageType) != "" && m.logger != nil {
				m.logger.Warn("telemetry storage directive ignored because DATABASE_URL or a storage registry is configured",
					zap.String("directive_storage_type", m.TelemetryConfig.StorageType),
					zap.String("directive_storage_path", m.TelemetryConfig.StoragePath),
					zap.String("active_source", "storage registry"),
				)
			}
			tStore, err := m.storageRegistry.TelemetryStore(context.Background())
			if err != nil {
				return fmt.Errorf("provision telemetry store from registry: %w", err)
			}
			m.telemetryStore = tStore
		} else if m.TelemetryConfig != nil {
			storageType := strings.ToLower(m.TelemetryConfig.StorageType)
			if storageType == "clickhouse" {
				chStore, err := clickhouse.NewClickHouseStore(clickhouse.ClickHouseConfig{
					URL: m.TelemetryConfig.StoragePath,
				})
				if err != nil {
					return fmt.Errorf("provision clickhouse telemetry store: %w", err)
				}
				m.telemetryStore = chStore
			} else {
				retention := time.Duration(m.TelemetryConfig.Retention)
				if retention <= 0 {
					retention = 30 * 24 * time.Hour
				}
				dbPath := m.TelemetryConfig.StoragePath
				if dbPath == "" {
					dbPath = "raiwall-telemetry.db"
				}
				sqStore, err := sqlite.NewSQLiteStore(sqlite.TelemetryConfig{
					DSN:       dbPath,
					Retention: retention,
				})
				if err != nil {
					return fmt.Errorf("provision sqlite telemetry store: %w", err)
				}
				m.telemetryStore = sqStore
			}
		}
	}

	if m.alertEngine == nil && m.TelemetryConfig != nil && len(m.TelemetryConfig.AlertChannels) > 0 {
		var channels []alerts.AlertChannel
		for _, ch := range m.TelemetryConfig.AlertChannels {
			cooldown := time.Duration(ch.Cooldown)
			if cooldown <= 0 {
				cooldown = 5 * time.Minute
			}
			channels = append(channels, alerts.AlertChannel{
				Name:     ch.Name,
				URL:      ch.URL,
				Events:   ch.Events,
				Cooldown: cooldown,
			})
		}
		m.alertEngine = alerts.NewAlertEngine(channels, 5*time.Minute, nil)
	}

	if m.ringBuffer == nil {
		bufSize := telemetry.DefaultRingBufferCapacity
		flushInterval := telemetry.DefaultFlushInterval
		if m.TelemetryConfig != nil {
			if m.TelemetryConfig.BufferSize > 0 {
				bufSize = m.TelemetryConfig.BufferSize
			}
			if m.TelemetryConfig.FlushInterval > 0 {
				flushInterval = time.Duration(m.TelemetryConfig.FlushInterval)
			}
		}

		m.ringBuffer = telemetry.NewRingBuffer(telemetry.RingBufferConfig{
			Capacity:      bufSize,
			BatchSize:     telemetry.DefaultBatchSize,
			FlushInterval: flushInterval,
			Handler: func(events []*telemetry.ForensicEvent) error {
				if m.telemetryStore != nil {
					return m.telemetryStore.SaveBatch(context.Background(), events)
				}
				return nil
			},
		})
	}

	if m.telemetryAPI == nil {
		m.telemetryAPI = api.NewTelemetryAPI(m.telemetryStore, m.streamer, m.metrics)
	}

	return nil
}
