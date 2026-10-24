package caddy

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
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

	if m.templateManager == nil {
		m.templateManager = templates.NewTemplateManager()
	}
	if m.controlStore != nil {
		_ = m.templateManager.LoadFromStore(context.Background(), m.controlStore)
		if m.ipGroupMgr != nil {
			m.syncIPGroupsWithStore(m.controlStore, m.ipGroupMgr)
		}
		// Bootstrap the app-auth clearance signing secret so the next
		// snapshot compile carries it into the data plane.
		if _, err := m.resolveAppAuthSecret(context.Background()); err != nil && m.logger != nil {
			m.logger.Warn("failed to bootstrap app auth session secret", zap.Error(err))
		}
	}

	if m.controlAPI != nil {
		if m.banManager != nil {
			m.controlAPI.SetBanManager(m.banManager)
		}
		if m.waitingRoom != nil {
			m.controlAPI.SetWaitingRoom(m.waitingRoom)
		}
		if m.ipGroupMgr != nil {
			m.controlAPI.SetIPGroupManager(m.ipGroupMgr)
		}
		if m.templateManager != nil {
			m.controlAPI.SetTemplateManager(m.templateManager)
		}
	}

	if m.upstreamRegistry == nil {
		m.upstreamRegistry = NewUpstreamRegistry()
	}

	if m.controlStore != nil && m.discoveryCataloger == nil {
		m.discoveryCataloger = NewAPIDiscoveryCataloger(m.controlStore, m.logger, 2*time.Second)
	}

	if m.ipGroupMgr != nil && m.controlStore != nil {
		m.syncIPGroupsWithStore(m.controlStore, m.ipGroupMgr)
	}

	// Compile the portal-wide gate once the control store is available.
	m.buildGlobalAuthGate()

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

func (m *Middleware) syncIPGroupsWithStore(store control.ControlStore, mgr *acl.IPGroupManager) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	storedGroups, err := store.ListIPGroups(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("failed to query stored IP groups", zap.Error(err))
		}
		return
	}

	storedMap := make(map[string]control.IPGroupRecord)
	for _, g := range storedGroups {
		storedMap[g.Name] = g
	}

	// 1. Seed built-in groups from memory into store if not already present
	for _, bg := range mgr.ListGroups() {
		if _, exists := storedMap[bg.Name]; !exists {
			rec := control.IPGroupRecord{
				ID:          bg.ID,
				Name:        bg.Name,
				Description: bg.Description,
				Type:        bg.Type,
				CreatedAt:   bg.CreatedAt,
				UpdatedAt:   bg.UpdatedAt,
			}
			if err := store.CreateIPGroup(ctx, rec); err == nil {
				storedMap[bg.Name] = rec
				for _, entry := range mgr.ListEntries(bg.ID) {
					_ = store.CreateIPGroupEntry(ctx, control.IPGroupEntryRecord{
						ID:        entry.ID,
						GroupID:   rec.ID,
						CIDR:      entry.CIDR,
						Comment:   entry.Comment,
						CreatedAt: entry.CreatedAt,
					})
				}
			}
		}
	}

	// 2. Load stored groups and entries into in-memory manager
	for _, sg := range storedGroups {
		grp := mgr.EnsureGroup(sg.ID, sg.Name, sg.Description, sg.Type)
		targetID := sg.ID
		if grp != nil {
			targetID = grp.ID
		}
		entries, err := store.ListIPGroupEntries(ctx, sg.ID)
		if err == nil {
			for _, e := range entries {
				_, _ = mgr.AddCIDR(targetID, e.CIDR, e.Comment)
			}
		}
	}
}
