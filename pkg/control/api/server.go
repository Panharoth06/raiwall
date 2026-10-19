package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
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
}

// NewServer initializes a new Control Plane API server with Chi routing.
func NewServer(store *db.Store, hmacSecret []byte) *Server {
	authMgr := NewAuthManager(store, hmacSecret)
	s := &Server{
		store:   store,
		authMgr: authMgr,
		router:  chi.NewRouter(),
	}

	s.routes()
	return s
}

// SetClusterPublisher sets the distributed cluster event publisher.
func (s *Server) SetClusterPublisher(pub ClusterPublisher) {
	s.clusterPublisher = pub
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

	// Auth Endpoints (Public login)
	r.Post("/api/v1/auth/login", s.handleLogin)

	// Protected API Routes with Auth and 2-Tier RBAC Middleware
	r.Group(func(api chi.Router) {
		api.Use(s.authMgr.AuthMiddleware)

		// Auth
		api.Post("/api/v1/auth/logout", s.handleLogout)
		api.Get("/api/v1/auth/me", s.handleAuthMe)

		// Status
		api.Get("/api/v1/status", s.handleStatus)

		// Sites (Apps) CRUD
		api.Get("/api/v1/sites", s.handleListSites)
		api.Post("/api/v1/sites", s.handleCreateSite)
		api.Get("/api/v1/sites/{id}", s.handleGetSite)
		api.Put("/api/v1/sites/{id}", s.handleUpdateSite)
		api.Delete("/api/v1/sites/{id}", s.handleDeleteSite)

		// Exceptions CRUD & Test Dry-run
		api.Get("/api/v1/exceptions", s.handleListExceptions)
		api.Post("/api/v1/exceptions", s.handleCreateException)
		api.Get("/api/v1/exceptions/{id}", s.handleGetException)
		api.Put("/api/v1/exceptions/{id}", s.handleUpdateException)
		api.Delete("/api/v1/exceptions/{id}", s.handleDeleteException)
		api.Post("/api/v1/exceptions/test", s.handleTestException)

		// ACL Rules CRUD & Expr Test Dry-run
		api.Get("/api/v1/acls", s.handleListACLRules)
		api.Post("/api/v1/acls", s.handleCreateACLRule)
		api.Get("/api/v1/acls/{id}", s.handleGetACLRule)
		api.Put("/api/v1/acls/{id}", s.handleUpdateACLRule)
		api.Delete("/api/v1/acls/{id}", s.handleDeleteACLRule)
		api.Post("/api/v1/acls/test", s.handleTestACL)

		// Rate Policies CRUD
		api.Get("/api/v1/policies/rate", s.handleListRatePolicies)
		api.Post("/api/v1/policies/rate", s.handleCreateRatePolicy)
		api.Get("/api/v1/policies/rate/{id}", s.handleGetRatePolicy)
		api.Put("/api/v1/policies/rate/{id}", s.handleUpdateRatePolicy)
		api.Delete("/api/v1/policies/rate/{id}", s.handleDeleteRatePolicy)

		// Bot Configs CRUD
		api.Get("/api/v1/policies/bot", s.handleListBotConfigs)
		api.Post("/api/v1/policies/bot", s.handleCreateBotConfig)
		api.Get("/api/v1/policies/bot/{id}", s.handleGetBotConfig)
		api.Put("/api/v1/policies/bot/{id}", s.handleUpdateBotConfig)
		api.Delete("/api/v1/policies/bot/{id}", s.handleDeleteBotConfig)

		// Staged Deployment Diff, Apply, Rollback & Snapshot History
		api.Get("/api/v1/config/draft/diff", s.handleGetConfigDiff)
		api.Post("/api/v1/config/apply", s.handleApplyConfig)
		api.Post("/api/v1/config/rollback/{version}", s.handleRollbackConfig)
		api.Get("/api/v1/config/snapshots", s.handleListSnapshots)

		// API Keys CRUD
		api.Get("/api/v1/apikeys", s.handleListAPIKeys)
		api.Post("/api/v1/apikeys", s.handleCreateAPIKey)
		api.Delete("/api/v1/apikeys/{id}", s.handleDeleteAPIKey)
	})
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

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}
