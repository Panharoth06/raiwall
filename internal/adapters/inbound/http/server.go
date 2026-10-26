package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/Panharoth06/raiwall/internal/core/rate"
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

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}
