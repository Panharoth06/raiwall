package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/Panharoth06/raiwall/pkg/control/mcp"
	"github.com/go-chi/chi/v5"
)

// ClusterPublisher broadcasts config version changes to other cluster nodes.
type ClusterPublisher interface {
	PublishVersion(ctx context.Context, version uint64) error
}

// Server provides the HTTP handler for the Raiwall Control Plane REST API.
type Server struct {
	store            *db.Store
	authMgr          *AuthManager
	router           *chi.Mux
	clusterPublisher ClusterPublisher
	mcpServer        *mcp.Server
}

// NewServer initializes a new Control Plane API server with Chi routing.
func NewServer(store *db.Store, hmacSecret []byte) *Server {
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

// Store returns the underlying SQLite DB store.
func (s *Server) Store() *db.Store {
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

func (s *Server) routes() {
	r := s.router

	// OpenAPI 3.1 & Interactive Documentation (Public)
	r.Get("/.raiwall/api/openapi.json", ServeOpenAPISpec)
	r.Get("/.raiwall/api/docs", ServeScalarDocs)
	r.Get("/.raiwall/api/swagger", ServeSwaggerDocs)
	r.Get("/api/openapi.json", ServeOpenAPISpec)
	r.Get("/api/docs", ServeScalarDocs)
	r.Get("/api/swagger", ServeSwaggerDocs)

	// MCP Server Protocol Endpoints (Protected by API Key / Session)
	registerMCPRoutes := func(mcpRouter chi.Router) {
		mcpRouter.Use(s.authMgr.AuthMiddleware)
		mcpRouter.Get("/", s.mcpServer.ServeSSE)
		mcpRouter.Post("/message", s.handleMCPMessage)
	}

	r.Route("/.raiwall/api/mcp", registerMCPRoutes)
	r.Route("/api/mcp", registerMCPRoutes)
	r.Route("/api/v1/mcp", registerMCPRoutes)
	r.Route("/.raiwall/api/v1/mcp", registerMCPRoutes)

	registerAPIRoutes := func(sub chi.Router) {
		sub.Post("/auth/login", s.handleLogin)

		sub.Group(func(api chi.Router) {
			api.Use(s.authMgr.AuthMiddleware)

			// Auth
			api.Post("/auth/logout", s.handleLogout)
			api.Get("/auth/me", s.handleAuthMe)

			// Status & Cluster
			api.Get("/status", s.handleStatus)
			api.Get("/cluster/status", s.handleClusterStatus)

			// Sites (Apps) CRUD
			api.Get("/sites", s.handleListSites)
			api.Post("/sites", s.handleCreateSite)
			api.Get("/sites/{id}", s.handleGetSite)
			api.Put("/sites/{id}", s.handleUpdateSite)
			api.Delete("/sites/{id}", s.handleDeleteSite)

			// Exceptions CRUD & Test Dry-run
			api.Get("/exceptions", s.handleListExceptions)
			api.Post("/exceptions", s.handleCreateException)
			api.Get("/exceptions/{id}", s.handleGetException)
			api.Put("/exceptions/{id}", s.handleUpdateException)
			api.Delete("/exceptions/{id}", s.handleDeleteException)
			api.Post("/exceptions/test", s.handleTestException)
			api.Post("/exceptions/dry-run", s.handleTestException)

			// ACL Rules CRUD & Expr Test Dry-run
			api.Get("/acls", s.handleListACLRules)
			api.Post("/acls", s.handleCreateACLRule)
			api.Get("/acls/{id}", s.handleGetACLRule)
			api.Put("/acls/{id}", s.handleUpdateACLRule)
			api.Delete("/acls/{id}", s.handleDeleteACLRule)
			api.Post("/acls/test", s.handleTestACL)
			api.Post("/acls/dry-run", s.handleTestACL)

			// Unified Policies & Sub-Policies CRUD
			api.Get("/policies", s.handleGetUnifiedPolicies)
			api.Put("/policies", s.handleUpdateUnifiedPolicies)
			api.Get("/policies/rate", s.handleListRatePolicies)
			api.Post("/policies/rate", s.handleCreateRatePolicy)
			api.Get("/policies/rate/{id}", s.handleGetRatePolicy)
			api.Put("/policies/rate/{id}", s.handleUpdateRatePolicy)
			api.Delete("/policies/rate/{id}", s.handleDeleteRatePolicy)

			// Bot Configs CRUD
			api.Get("/policies/bot", s.handleListBotConfigs)
			api.Post("/policies/bot", s.handleCreateBotConfig)
			api.Get("/policies/bot/{id}", s.handleGetBotConfig)
			api.Put("/policies/bot/{id}", s.handleUpdateBotConfig)
			api.Delete("/policies/bot/{id}", s.handleDeleteBotConfig)

			// Staged Deployment Diff, Apply, Rollback & Snapshot History
			api.Get("/config/draft/diff", s.handleGetConfigDiff)
			api.Post("/config/apply", s.handleApplyConfig)
			api.Post("/config/rollback/{version}", s.handleRollbackConfig)
			api.Get("/config/snapshots", s.handleListSnapshots)
			api.Get("/config/history", s.handleListSnapshots)

			// API Keys CRUD
			api.Get("/apikeys", s.handleListAPIKeys)
			api.Post("/apikeys", s.handleCreateAPIKey)
			api.Delete("/apikeys/{id}", s.handleDeleteAPIKey)
		})
	}

	r.Route("/api/v1", registerAPIRoutes)
	r.Route("/.raiwall/api/v1", registerAPIRoutes)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user.IsActive != 1 {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if !CheckPassword(req.Password, user.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	cookie, err := s.authMgr.GenerateSessionCookie(&user, 24*time.Hour)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create session: "+err.Error())
		return
	}

	http.SetCookie(w, cookie)
	respondJSON(w, http.StatusOK, map[string]any{
		"message":  "login successful",
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	respondJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	authCtx, ok := AuthFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	respondJSON(w, http.StatusOK, authCtx)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := config.GetActiveSnapshot()
	var ver uint64
	var mode config.RunMode = config.ModeDefense
	if snap != nil {
		ver = snap.Version
		mode = snap.DefaultMode
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":         "healthy",
		"active_version": ver,
		"mode":           mode,
		"timestamp":      time.Now().UTC(),
	})
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	snap := config.GetActiveSnapshot()
	var ver uint64 = 1
	if snap != nil {
		ver = snap.Version
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"mode":            "standalone",
		"redis_connected": false,
		"active_version":  ver,
		"channel":         "raiwall:cluster",
	})
}

func (s *Server) handleMCPMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read request body: "+err.Error())
		return
	}

	var req mcp.JSONRPCRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &mcp.JSONRPCError{Code: -32700, Message: "parse error: " + err.Error()},
		})
		return
	}

	// Role-based authorization for MCP tools
	if authCtx, ok := AuthFromContext(r.Context()); ok && authCtx.Role == "viewer" {
		if req.Method == "tools/call" {
			var callParams struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(req.Params, &callParams)
			// Disallow mutating tools for viewer
			if callParams.Name == "create_exception_rule" || callParams.Name == "apply_configuration" || callParams.Name == "rollback_configuration" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &mcp.JSONRPCError{Code: -32603, Message: fmt.Sprintf("role viewer is not authorized to execute mutating tool %q", callParams.Name)},
				})
				return
			}
		}
	}

	resp := s.mcpServer.HandleRequest(r.Context(), &req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}
