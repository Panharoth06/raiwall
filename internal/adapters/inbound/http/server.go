package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
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
	store            *sqlite.Store
	authMgr          *AuthManager
	router           *chi.Mux
	clusterPublisher ClusterPublisher
	mcpServer        *mcp.Server
	banManager       *rate.BanManager
	waitingRoom      *rate.WaitingRoomManager
}

// NewServer initializes a new Control Plane API server with Chi routing.
func NewServer(store *sqlite.Store, hmacSecret []byte) *Server {
	authMgr := NewAuthManager(store, hmacSecret)
	s := &Server{
		store:     store,
		authMgr:   authMgr,
		router:    chi.NewRouter(),
		mcpServer: mcp.NewServer(store),
	}

	s.routes()
	return s
}

// SetClusterPublisher sets the distributed cluster event publisher.
func (s *Server) SetClusterPublisher(pub ClusterPublisher) {
	s.clusterPublisher = pub
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

// Store returns the underlying SQLite DB store.
func (s *Server) Store() *sqlite.Store {
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
