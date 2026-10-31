package api

import (
	"github.com/go-chi/chi/v5"
)

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
			api.Use(s.DeclarativeGuardMiddleware)
			api.Use(s.AutoApplyMiddleware)

			// Auth
			api.Post("/auth/logout", s.handleLogout)
			api.Get("/auth/me", s.handleAuthMe)

			// Status & Cluster
			api.Get("/status", s.handleStatus)
			api.Put("/system/auto-apply", s.handleUpdateAutoApply)
			api.Get("/cluster/status", s.handleClusterStatus)

			// Synthetic request evaluation against the live WAF engine.
			api.Post("/rules/test", s.handleRuleTest)

			// Semantic Detection Matrix (SafeLine parity: 14 modules, 4 modes)
			api.Get("/detector", s.handleGetDetector)
			api.Put("/detector/modules/{module}", s.handleUpdateDetectorModule)
			api.Get("/detector/apps/{id}", s.handleGetAppPolicy)
			api.Put("/detector/apps/{id}", s.handleUpdateAppPolicy)

			// Detection workspace: posture, presets, and global/per-site policies.
			api.Get("/detection/status", s.handleGetDetectionStatus)
			api.Get("/detection/presets", s.handleListDetectionPresets)
			api.Get("/detection/policy", s.handleGetDetectionPolicy)
			api.Put("/detection/policy", s.handleUpdateDetectionPolicy)
			api.Get("/detection/policies/apps", s.handleListAppDetectionPolicies)
			api.Get("/detection/policies/apps/{id}", s.handleGetAppDetectionPolicy)
			api.Put("/detection/policies/apps/{id}", s.handleUpdateAppDetectionPolicy)
			api.Delete("/detection/policies/apps/{id}", s.handleDeleteAppDetectionPolicy)

			// Unified rule catalog and per-rule overrides.
			api.Get("/detection/rules", s.handleListDetectionRules)
			api.Post("/detection/rules/bulk", s.handleBulkDetectionRules)
			api.Get("/detection/rules/{id}", s.handleGetDetectionRule)
			api.Patch("/detection/rules/{id}", s.handleUpdateDetectionRule)
			api.Delete("/detection/rules/{id}/override", s.handleResetDetectionRuleOverride)

			// Imported rule packs.
			api.Get("/detection/packs", s.handleListDetectionPacks)
			api.Post("/detection/packs/validate", s.handleValidateDetectionPack)
			api.Post("/detection/packs", s.handleCreateDetectionPack)
			api.Put("/detection/packs/{id}", s.handleUpdateDetectionPack)
			api.Delete("/detection/packs/{id}", s.handleDeleteDetectionPack)

			// Inner Rules (CVE virtual patches & external plugin feeds)
			api.Get("/inner-rules", s.handleListInnerRules)
			api.Get("/inner-rules/plugins", s.handleListInnerRulePlugins)
			api.Post("/inner-rules/import", s.handleImportInnerRules)
			api.Put("/inner-rules/{id}", s.handleUpdateInnerRule)
			api.Put("/inner-rules/categories/{category}", s.handleUpdateInnerRuleCategory)

			// Identity Directory (end-user accounts + external IdPs)
			api.Get("/identity/users", s.handleListIdentityUsers)
			api.Post("/identity/users", s.handleCreateIdentityUser)
			api.Get("/identity/users/{id}", s.handleGetIdentityUser)
			api.Put("/identity/users/{id}", s.handleUpdateIdentityUser)
			api.Delete("/identity/users/{id}", s.handleDeleteIdentityUser)
			api.Post("/identity/users/{id}/password-reset", s.handleResetIdentityUserPassword)
			api.Post("/identity/users/{id}/totp-reset", s.handleResetIdentityUserTOTP)

			// External Identity Provider Connectors (LDAP / GitHub / OIDC)
			api.Get("/identity/providers", s.handleListIdentityProviders)
			api.Post("/identity/providers", s.handleCreateIdentityProvider)
			api.Put("/identity/providers/{id}", s.handleUpdateIdentityProvider)
			api.Delete("/identity/providers/{id}", s.handleDeleteIdentityProvider)

			// Authentication Audit Log
			api.Get("/identity/auth-events", s.handleListIdentityAuthEvents)

			// Sites (Apps) CRUD
			api.Get("/sites", s.handleListSites)
			api.Post("/sites", s.handleCreateSite)
			api.Get("/sites/{id}", s.handleGetSite)
			api.Put("/sites/{id}", s.handleUpdateSite)
			api.Delete("/sites/{id}", s.handleDeleteSite)

			// Managed TLS Certificates
			registerCertificateRoutes(api, "/certificates", s)
			// Documented compatibility surface (docs/api-specification.md).
			registerCertificateRoutes(api, "/open/cert", s)

			// Site Forwarding Rules
			api.Get("/sites/{id}/forwarding-rules", s.handleListForwardingRules)
			api.Post("/sites/{id}/forwarding-rules", s.handleCreateForwardingRule)
			api.Put("/sites/{id}/forwarding-rules/{rule_id}", s.handleUpdateForwardingRule)
			api.Delete("/sites/{id}/forwarding-rules/{rule_id}", s.handleDeleteForwardingRule)

			// Site Auto-Discovered API Resources
			api.Get("/sites/{id}/resources", s.handleListAPIResources)
			api.Delete("/sites/{id}/resources/{resource_id}", s.handleDeleteAPIResource)

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

			// Named IP Groups CRUD & Dynamic BART Integration
			api.Get("/ip-groups", s.handleListIPGroups)
			api.Post("/ip-groups", s.handleCreateIPGroup)
			api.Get("/ip-groups/{id}", s.handleGetIPGroup)
			api.Put("/ip-groups/{id}", s.handleUpdateIPGroup)
			api.Delete("/ip-groups/{id}", s.handleDeleteIPGroup)
			api.Post("/ip-groups/{id}/entries", s.handleAddIPGroupEntry)
			api.Delete("/ip-groups/{id}/entries/{entryId}", s.handleDeleteIPGroupEntry)

			// Custom Response Templates CRUD & Preview
			api.Get("/templates", s.handleListTemplates)
			api.Get("/templates/{statusCode}", s.handleGetTemplate)
			api.Put("/templates/{statusCode}", s.handleUpdateTemplate)
			api.Post("/templates/{statusCode}/preview", s.handlePreviewTemplate)
			api.Post("/templates/{statusCode}/reset", s.handleResetTemplate)

			// Unified Policies & Sub-Policies CRUD
			api.Get("/policies", s.handleGetUnifiedPolicies)
			api.Put("/policies", s.handleUpdateUnifiedPolicies)
			api.Get("/policies/rate", s.handleListRatePolicies)
			api.Post("/policies/rate", s.handleCreateRatePolicy)
			api.Get("/policies/rate/{id}", s.handleGetRatePolicy)
			api.Put("/policies/rate/{id}", s.handleUpdateRatePolicy)
			api.Delete("/policies/rate/{id}", s.handleDeleteRatePolicy)

			// Volumetric Defense & Active Banned Clients
			api.Get("/rate/bans", s.handleListBans)
			api.Post("/rate/bans/release", s.handleReleaseBan)
			api.Post("/rate/bans/release-all", s.handleReleaseAllBans)

			// Virtual Waiting Room Telemetry
			api.Get("/waiting-room/metrics", s.handleGetWaitingRoomMetrics)

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
