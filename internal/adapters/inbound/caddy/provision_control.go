package caddy

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (m *Middleware) provisionControl(_ caddy.Context) error {
	if m.controlAPI == nil {
		dbDSN := "file:raiwall_control.db?_pragma=busy_timeout(5000)"
		var secret []byte
		if m.ControlConfig != nil {
			if m.ControlConfig.DBPath != "" {
				dbDSN = m.ControlConfig.DBPath
			}
			if m.ControlConfig.HMACSecret != "" {
				secret = []byte(m.ControlConfig.HMACSecret)
			}
		}
		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("failed to initialize control plane database", zap.Error(err))
			}
		} else {
			m.controlStore = store
			m.controlAPI = api.NewServer(store, secret)
			m.ensureInitialAdminUser(store)
		}
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

func (m *Middleware) ensureInitialAdminUser(store *sqlite.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	users, err := store.ListUsers(ctx)
	if err == nil && len(users) == 0 {
		hash, err := api.HashPassword("admin")
		if err == nil {
			now := time.Now().UTC()
			_ = store.CreateUser(ctx, sqlite.CreateUserParams{
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
