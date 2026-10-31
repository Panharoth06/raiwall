package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/go-chi/chi/v5"
)

// ClusterPublisher broadcasts config version changes and ban events to other cluster nodes.
type ClusterPublisher interface {
	PublishVersion(ctx context.Context, version uint64) error
	PublishBan(ctx context.Context, entry *rate.BanEntry) error
	PublishUnblock(ctx context.Context, target string) error
	PublishUnblockAll(ctx context.Context) error
}

// Server provides the HTTP handler for the Raiwall Control Plane REST API.
type Server struct {
	store            control.ControlStore
	authMgr          *AuthManager
	router           *chi.Mux
	clusterPublisher ClusterPublisher
	mcpServer        *mcp.Server
	banManager       *rate.BanManager
	waitingRoom      *rate.WaitingRoomManager
	ipGroupMgr       *acl.IPGroupManager
	templateMgr      *templates.TemplateManager
	certReloader     func(context.Context) error
	certReconciler   func(context.Context)
	ruleTester       func(*waf.RequestContext) (*waf.Verdict, error)
	autoApply        bool
	applyMu          sync.Mutex

	// Coraza process defaults, injected by the Caddy data plane. The detection
	// status/policy endpoints use these when no explicit policy row exists.
	crsEngineAvailable bool
	crsDefaultEnabled  bool
	crsDefaultMode     string
	crsDefaultParanoia int
	crsDefaultInbound  int
	crsDefaultOutbound int
}

// NewServer initializes a new Control Plane API server with Chi routing.
func NewServer(store control.ControlStore, hmacSecret []byte) *Server {
	authMgr := NewAuthManager(store, hmacSecret)
	tmplMgr := templates.NewTemplateManager()
	_ = tmplMgr.LoadFromStore(context.Background(), store)

	s := &Server{
		store:       store,
		authMgr:     authMgr,
		router:      chi.NewRouter(),
		mcpServer:   mcp.NewServer(store),
		templateMgr: tmplMgr,
	}

	s.routes()
	return s
}

// SetClusterPublisher sets the distributed cluster event publisher.
func (s *Server) SetClusterPublisher(pub ClusterPublisher) {
	s.clusterPublisher = pub
}

// SetAutoApply enables committing a snapshot after every successful
// configuration mutation. It must be called before routes start serving.
func (s *Server) SetAutoApply(enabled bool) {
	s.autoApply = enabled
}

// SetCRSDefaults records the process-level CRS configuration so the detection
// endpoints can resolve policy when no explicit override exists.
func (s *Server) SetCRSDefaults(enabled bool, mode string, paranoia, inbound, outbound int) {
	s.crsDefaultEnabled = enabled
	s.crsDefaultMode = mode
	s.crsDefaultParanoia = paranoia
	s.crsDefaultInbound = inbound
	s.crsDefaultOutbound = outbound
}

// SetCRSEngineAvailable reports whether the Coraza engine is provisioned in
// this data plane (waf.crs.enabled is true).
func (s *Server) SetCRSEngineAvailable(available bool) {
	s.crsEngineAvailable = available
}

// AutoApplyEnabled reports whether mutations are committed automatically.
func (s *Server) AutoApplyEnabled() bool {
	return s.autoApply
}

// publishVersion notifies cluster peers about a newly active snapshot.
func (s *Server) publishVersion(version uint64) {
	if s.clusterPublisher == nil {
		return
	}
	go func() {
		_ = s.clusterPublisher.PublishVersion(context.Background(), version)
	}()
}

// SetCertificateReloader installs the TLS provider refresh callback invoked
// after certificate records change.
func (s *Server) SetCertificateReloader(fn func(context.Context) error) {
	s.certReloader = fn
}

// reloadCertificates refreshes the data-plane certificate index, if wired.
func (s *Server) reloadCertificates(ctx context.Context) {
	if s.certReloader == nil {
		return
	}
	_ = s.certReloader(ctx)
}

// SetCertificateReconciler installs the callback that renews/obtains
// certificates in the data plane.
func (s *Server) SetCertificateReconciler(fn func(context.Context)) {
	s.certReconciler = fn
}

// ClusterPublisher returns the configured cluster event publisher.
func (s *Server) ClusterPublisher() ClusterPublisher {
	return s.clusterPublisher
}

// SetBanManager sets the active BanManager.
func (s *Server) SetBanManager(bm *rate.BanManager) {
	s.banManager = bm
}

// BanManager returns the active BanManager.
func (s *Server) BanManager() *rate.BanManager {
	return s.banManager
}

// SetWaitingRoom sets the active WaitingRoomManager.
func (s *Server) SetWaitingRoom(wm *rate.WaitingRoomManager) {
	s.waitingRoom = wm
}

// WaitingRoom returns the active WaitingRoomManager.
func (s *Server) WaitingRoom() *rate.WaitingRoomManager {
	return s.waitingRoom
}

// SetIPGroupManager sets the active IPGroupManager and synchronizes persisted groups from the store.
func (s *Server) SetIPGroupManager(mgr *acl.IPGroupManager) {
	s.ipGroupMgr = mgr
	if s.ipGroupMgr != nil && s.store != nil {
		s.syncIPGroupsFromStore(context.Background())
	}
}

func (s *Server) syncIPGroupsFromStore(ctx context.Context) {
	groups, err := s.store.ListIPGroups(ctx)
	if err != nil {
		return
	}
	for _, grp := range groups {
		entries, err := s.store.ListIPGroupEntries(ctx, grp.ID)
		if err != nil {
			continue
		}
		memGrp := s.ipGroupMgr.EnsureGroup(grp.ID, grp.Name, grp.Description, grp.Type)
		targetID := grp.ID
		if memGrp != nil {
			targetID = memGrp.ID
		}
		for _, e := range entries {
			_, _ = s.ipGroupMgr.AddCIDR(targetID, e.CIDR, e.Comment)
		}
	}
}

// IPGroupManager returns the active IPGroupManager.
func (s *Server) IPGroupManager() *acl.IPGroupManager {
	return s.ipGroupMgr
}

// SetTemplateManager sets the active TemplateManager.
func (s *Server) SetTemplateManager(mgr *templates.TemplateManager) {
	s.templateMgr = mgr
}

// TemplateManager returns the active TemplateManager.
func (s *Server) TemplateManager() *templates.TemplateManager {
	return s.templateMgr
}

// Store returns the underlying ControlStore.
func (s *Server) Store() control.ControlStore {
	return s.store
}

// MCPServer returns the underlying MCP server.
func (s *Server) MCPServer() *mcp.Server {
	return s.mcpServer
}

// Router returns the Chi router instance.
func (s *Server) Router() *chi.Mux {
	return s.router
}

// ServeHTTP delegates request handling to the Chi router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// AuthenticateRequest resolves the request principal using the control-plane
// auth manager. Adjacent surfaces (telemetry, metrics, SSE) share credentials
// but are dispatched before the chi router, so they call this directly.
func (s *Server) AuthenticateRequest(r *http.Request) (*AuthContext, error) {
	if s == nil || s.authMgr == nil {
		return nil, errors.New("control plane authentication unavailable")
	}
	return s.authMgr.Authenticate(r)
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}
