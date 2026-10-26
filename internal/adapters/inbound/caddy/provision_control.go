package caddy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var certDeployHookOnce sync.Once

func (m *Middleware) provisionControl(ctx caddy.Context) error {
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
		// Restore the last committed snapshot so applications keep routing
		// across restarts without requiring an operator to re-apply.
		m.restoreActiveSnapshot()
		// Reconcile file-declared resources once per process and deploy only
		// when the compiled content actually changed.
		if err := m.syncDeclarative(); err != nil {
			return err
		}
		m.installCertificateProvider(ctx)
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

// restoreActiveSnapshot loads the newest committed snapshot into the data plane
// on startup so routing survives process restarts.
func (m *Middleware) restoreActiveSnapshot() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	record, err := m.controlStore.GetLatestSnapshot(ctx)
	if err != nil || record.SnapshotData == "" {
		return
	}
	var snap control.ConfigSnapshot
	if err := json.Unmarshal([]byte(record.SnapshotData), &snap); err != nil {
		if m.logger != nil {
			m.logger.Warn("failed to parse stored configuration snapshot", zap.Error(err))
		}
		return
	}
	snap.RebuildIndex()
	control.SetActiveSnapshot(&snap)
	if m.logger != nil {
		m.logger.Info("restored active configuration snapshot", zap.Int64("version", record.Version))
	}
}

// installCertificateProvider wires dynamic SNI certificate resolution and
// post-deploy reconciliation into the data plane.
func (m *Middleware) installCertificateProvider(ctx caddy.Context) {
	tlsApp := tlsAppFromContext(ctx)

	provider, err := NewCertificateProvider(m.controlStore, tlsApp, m.logger)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("failed to initialize certificate provider", zap.Error(err))
		}
		return
	}
	currentCertProvider.Store(provider)

	if err := provider.Reload(context.Background()); err != nil && m.logger != nil {
		m.logger.Warn("failed to load managed certificates", zap.Error(err))
	}

	certDeployHookOnce.Do(func() {
		control.RegisterDeployHook(func(_ context.Context, _ *control.ConfigSnapshot) {
			if p := CurrentCertificateProvider(); p != nil {
				go p.Reconcile(context.Background())
			}
		})
	})
	go provider.Reconcile(context.Background())

	if m.controlAPI != nil {
		m.controlAPI.SetCertificateReloader(provider.Reload)
		m.controlAPI.SetCertificateReconciler(provider.Reconcile)
	}
}

func (m *Middleware) ensureInitialAdminUser(store control.ControlStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	users, err := store.ListUsers(ctx)
	if err != nil || len(users) > 0 {
		return
	}

	username := "admin"
	role := "admin"
	password := ""
	if m.ControlConfig != nil && m.ControlConfig.BootstrapAdmin != nil {
		admin := m.ControlConfig.BootstrapAdmin
		if admin.Username != "" {
			username = admin.Username
		}
		if admin.Role != "" {
			role = admin.Role
		}
		password = admin.Password
	}

	generated := false
	if password == "" {
		password = generateBootstrapPassword()
		generated = true
	}

	hash, err := api.HashPassword(password)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to hash initial admin password", zap.Error(err))
		}
		return
	}

	now := time.Now().UTC()
	err = store.CreateUser(ctx, control.UserRecord{
		ID:           uuid.NewString(),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to provision initial admin user", zap.Error(err))
		}
		return
	}

	if m.logger == nil {
		return
	}
	if generated {
		m.logger.Warn("auto-provisioned initial admin user with generated password; store it now, it will not be shown again",
			zap.String("username", username),
			zap.String("password", password),
			zap.String("remedy", "set control.bootstrap_admin.password, ${RAIWALL_ADMIN_PASSWORD}, or create a user with `raiwall admin create-user`"),
		)
		return
	}
	m.logger.Info("auto-provisioned initial admin user", zap.String("username", username))
}

// generateBootstrapPassword returns a 24-character URL-safe random password.
func generateBootstrapPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for any sane deployment; fall back to a
		// fixed-length random-looking value is not safe, so panic loudly.
		panic(fmt.Sprintf("generate bootstrap password: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
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

// tlsAppFromContext returns the provisioning TLS app, tolerating partially
// initialized contexts (tests provision the module directly).
func tlsAppFromContext(ctx caddy.Context) (app *caddytls.TLS) {
	defer func() {
		if recover() != nil {
			app = nil
		}
	}()
	if tlsModule, err := ctx.App("tls"); err == nil {
		if typed, ok := tlsModule.(*caddytls.TLS); ok {
			return typed
		}
	}
	return nil
}
