package caddy

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (m *Middleware) provisionControl(_ caddy.Context) error {
	if m.controlStore == nil {
		if m.storageRegistry != nil {
			store, err := m.storageRegistry.ControlStore(context.Background())
			if err != nil {
				return fmt.Errorf("provision control store from registry: %w", err)
			}
			m.controlStore = store
		} else {
			dbDSN := "file:raiwall_control.db?_pragma=busy_timeout(5000)"
			if m.ControlConfig != nil && m.ControlConfig.DBPath != "" {
				dbDSN = m.ControlConfig.DBPath
			}
			store, err := sqlite.InitDB(dbDSN)
			if err != nil {
				if m.logger != nil {
					m.logger.Warn("failed to initialize control plane database", zap.Error(err))
				}
			} else {
				m.controlStore = store
			}
		}
	}

	if m.controlAPI == nil && m.controlStore != nil {
		var secret []byte
		if m.ControlConfig != nil && m.ControlConfig.HMACSecret != "" {
			secret = []byte(m.ControlConfig.HMACSecret)
		}
		m.controlAPI = api.NewServer(m.controlStore, secret)
		m.ensureInitialAdminUser(m.controlStore)
	}

	if m.controlAPI != nil {
		if m.banManager != nil {
			m.controlAPI.SetBanManager(m.banManager)
		}
		if m.waitingRoom != nil {
			m.controlAPI.SetWaitingRoom(m.waitingRoom)
		}
	}

	if m.upstreamRegistry == nil {
		m.upstreamRegistry = NewUpstreamRegistry()
	}

	if m.controlStore != nil && m.discoveryCataloger == nil {
		m.discoveryCataloger = NewAPIDiscoveryCataloger(m.controlStore, m.logger, 2*time.Second)
	}

	return nil
}

func (m *Middleware) ensureInitialAdminUser(store control.ControlStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	users, err := store.ListUsers(ctx)
	if err == nil && len(users) == 0 {
		hash, err := api.HashPassword("admin")
		if err == nil {
			now := time.Now().UTC()
			_ = store.CreateUser(ctx, control.UserRecord{
				ID:           uuid.New().String(),
				Username:     "admin",
				PasswordHash: hash,
				Role:         "admin",
				IsActive:     1,
				CreatedAt:    now,
				UpdatedAt:    now,
			})
			if m.logger != nil {
				m.logger.Info("auto-provisioned initial admin user", zap.String("username", "admin"))
			}
		}
	}
}
