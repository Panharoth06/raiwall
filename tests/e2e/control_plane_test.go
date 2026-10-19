//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/api"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/Panharoth06/raiwall/pkg/control/mcp"
	"github.com/Panharoth06/raiwall/pkg/proxy"
)

type mockPublisher struct {
	mu        sync.Mutex
	published []uint64
}

func (m *mockPublisher) PublishVersion(ctx context.Context, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = append(m.published, version)
	return nil
}

func (m *mockPublisher) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.published)
}

func (m *mockPublisher) get(idx int) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < len(m.published) {
		return m.published[idx]
	}
	return 0
}

func TestControlPlane_E2E_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	dbDSN := fmt.Sprintf("file:test_e2e_cp_%d?mode=memory&cache=shared", time.Now().UnixNano())

	store, err := db.InitDB(dbDSN)
	require.NoError(t, err)
	defer store.Close()
	defer config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))

	// 1. Create Admin User
	hash, err := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	now := time.Now().UTC()
	err = store.CreateUser(ctx, db.CreateUserParams{
		ID:           uuid.NewString(),
		Username:     "admin_e2e",
		PasswordHash: string(hash),
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	// 2. Initialize API Server
	apiServer := api.NewServer(store, []byte("e2e_test_secret_32_bytes_long_ok"))
	pub := &mockPublisher{}
	apiServer.SetClusterPublisher(pub)
	router := apiServer.Router()

	doRequest := func(method, path string, payload any, cookie *http.Cookie) *httptest.ResponseRecorder {
		var bodyReader *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			bodyReader = bytes.NewReader(b)
		} else {
			bodyReader = bytes.NewReader([]byte{})
		}
		req := httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// 3. Authenticate and obtain session cookie
	loginRec := doRequest(http.MethodPost, "/.raiwall/api/v1/auth/login", map[string]string{
		"username": "admin_e2e",
		"password": "adminpass123",
	}, nil)
	require.Equal(t, http.StatusOK, loginRec.Code)

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "raiwall_session" {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "expected raiwall_session cookie")

	// Helper to make authenticated requests
	doAuth := func(method, path string, payload any) *httptest.ResponseRecorder {
		return doRequest(method, path, payload, sessionCookie)
	}

	// 4. Verify Scalar API Documentation endpoint
	docRec := doRequest(http.MethodGet, "/.raiwall/api/docs", nil, nil)
	require.Equal(t, http.StatusOK, docRec.Code)
	require.Contains(t, docRec.Body.String(), "@scalar/api-reference")

	// 5. Create a Site via API
	createSiteRec := doAuth(http.MethodPost, "/.raiwall/api/v1/sites", map[string]any{
		"name":      "Payment Gateway E2E",
		"hostnames": []string{"pay.example.com", "checkout.example.com"},
		"mode":      "defense",
		"upstreams": []map[string]any{
			{"dial": "10.0.0.1:8080", "weight": 2},
		},
		"block_status_code":   403,
		"offline_status_code": 503,
	})
	require.Equal(t, http.StatusCreated, createSiteRec.Code)

	// 6. Create an Exception Rule via API
	createExcRec := doAuth(http.MethodPost, "/.raiwall/api/v1/exceptions", map[string]any{
		"host":       "pay.example.com",
		"path":       "/checkout/search",
		"method":     "GET",
		"location":   "query",
		"param_name": "q",
		"reason":     "Search query false-positive",
		"rule_id":    "SQLI_UNION",
	})
	require.Equal(t, http.StatusCreated, createExcRec.Code)

	// 7. Check Staged Draft Diff
	diffRec := doAuth(http.MethodGet, "/.raiwall/api/v1/config/draft/diff", nil)
	require.Equal(t, http.StatusOK, diffRec.Code)
	var diffData struct {
		HasChanges bool     `json:"has_changes"`
		Added      []string `json:"added"`
	}
	err = json.NewDecoder(diffRec.Body).Decode(&diffData)
	require.NoError(t, err)
	require.True(t, diffData.HasChanges)
	require.NotEmpty(t, diffData.Added)

	// 8. Apply Configuration (Atomic Swap)
	applyRec := doAuth(http.MethodPost, "/.raiwall/api/v1/config/apply", map[string]string{
		"author":      "admin_e2e",
		"description": "Production deploy v1",
	})
	require.Equal(t, http.StatusOK, applyRec.Code)
	var applyData struct {
		Success bool   `json:"success"`
		Version uint64 `json:"version"`
	}
	err = json.NewDecoder(applyRec.Body).Decode(&applyData)
	require.NoError(t, err)
	require.True(t, applyData.Success)
	require.Equal(t, uint64(1), applyData.Version)

	// Verify active live snapshot in memory
	activeSnap := config.GetActiveSnapshot()
	require.NotNil(t, activeSnap)
	require.Equal(t, uint64(1), activeSnap.Version)
	require.Equal(t, 1, len(activeSnap.Apps))
	require.Equal(t, 1, len(activeSnap.Exceptions))
	require.Eventually(t, func() bool { return pub.count() >= 1 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), pub.get(0))

	// 9. Deploy a second revision
	applyRec2 := doAuth(http.MethodPost, "/.raiwall/api/v1/config/apply", map[string]string{
		"author":      "admin_e2e",
		"description": "Production deploy v2",
	})
	require.Equal(t, http.StatusOK, applyRec2.Code)
	activeSnap2 := config.GetActiveSnapshot()
	require.Equal(t, uint64(2), activeSnap2.Version)
	require.Eventually(t, func() bool { return pub.count() >= 2 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(2), pub.get(1))

	// 10. 1-Click Rollback to version 1
	rollbackRec := doAuth(http.MethodPost, "/.raiwall/api/v1/config/rollback/1", nil)
	require.Equal(t, http.StatusOK, rollbackRec.Code)

	revertedSnap := config.GetActiveSnapshot()
	require.Equal(t, uint64(1), revertedSnap.Version)
	require.Eventually(t, func() bool { return pub.count() >= 3 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), pub.get(2))
}

func TestControlPlane_E2E_ProxyMiddlewareAndMCP(t *testing.T) {
	ctx := context.Background()
	dbDSN := fmt.Sprintf("file:test_e2e_proxy_cp_%d?mode=memory&cache=shared", time.Now().UnixNano())

	// 1. Initialize Middleware with Control Plane configuration
	mw := &proxy.Middleware{
		Mode: "defense",
		ControlConfig: &proxy.ControlSettings{
			DBPath:     dbDSN,
			HMACSecret: "e2e_test_secret_32_bytes_long_ok",
		},
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: ctx})
	defer cancel()

	err := mw.Provision(caddyCtx)
	require.NoError(t, err)
	defer mw.Cleanup()
	defer config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))

	store := mw.ControlAPI().Store()
	require.NotNil(t, store)

	// Create admin and viewer users
	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminpass"), bcrypt.DefaultCost)
	require.NoError(t, err)
	viewerHash, err := bcrypt.GenerateFromPassword([]byte("viewerpass"), bcrypt.DefaultCost)
	require.NoError(t, err)

	now := time.Now().UTC()
	err = store.CreateUser(ctx, db.CreateUserParams{
		ID:           uuid.NewString(),
		Username:     "mw_admin",
		PasswordHash: string(adminHash),
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	err = store.CreateUser(ctx, db.CreateUserParams{
		ID:           uuid.NewString(),
		Username:     "mw_viewer",
		PasswordHash: string(viewerHash),
		Role:         "viewer",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	mockNext := &e2eNextHandler{handler: http.NotFoundHandler()}

	dispatch := func(method, path string, payload any, cookie *http.Cookie) *httptest.ResponseRecorder {
		var bodyReader *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			bodyReader = bytes.NewReader(b)
		} else {
			bodyReader = bytes.NewReader([]byte{})
		}
		req := httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		err := mw.ServeHTTP(rec, req, mockNext)
		require.NoError(t, err)
		return rec
	}

	// 2. Test OpenAPI Docs routed through Middleware
	docRec := dispatch(http.MethodGet, "/.raiwall/api/docs", nil, nil)
	require.Equal(t, http.StatusOK, docRec.Code)
	require.Contains(t, docRec.Body.String(), "@scalar/api-reference")

	// 3. Login Admin
	adminLoginRec := dispatch(http.MethodPost, "/.raiwall/api/v1/auth/login", map[string]string{
		"username": "mw_admin",
		"password": "adminpass",
	}, nil)
	require.Equal(t, http.StatusOK, adminLoginRec.Code)
	var adminCookie *http.Cookie
	for _, c := range adminLoginRec.Result().Cookies() {
		if c.Name == "raiwall_session" {
			adminCookie = c
			break
		}
	}
	require.NotNil(t, adminCookie)

	// 4. Login Viewer
	viewerLoginRec := dispatch(http.MethodPost, "/.raiwall/api/v1/auth/login", map[string]string{
		"username": "mw_viewer",
		"password": "viewerpass",
	}, nil)
	require.Equal(t, http.StatusOK, viewerLoginRec.Code)
	var viewerCookie *http.Cookie
	for _, c := range viewerLoginRec.Result().Cookies() {
		if c.Name == "raiwall_session" {
			viewerCookie = c
			break
		}
	}
	require.NotNil(t, viewerCookie)

	// 5. Role-based Access Control via Middleware: Viewer read-only & mutating blocks
	// Viewer can read sites
	viewerGetSites := dispatch(http.MethodGet, "/.raiwall/api/v1/sites", nil, viewerCookie)
	require.Equal(t, http.StatusOK, viewerGetSites.Code)

	// Viewer CANNOT mutate (create site) -> 403
	viewerPostSite := dispatch(http.MethodPost, "/.raiwall/api/v1/sites", map[string]any{
		"name": "Forbidden Site",
	}, viewerCookie)
	require.Equal(t, http.StatusForbidden, viewerPostSite.Code)

	// Viewer CAN logout successfully (regression fix: was 403 previously)
	viewerLogout := dispatch(http.MethodPost, "/.raiwall/api/v1/auth/logout", nil, viewerCookie)
	require.Equal(t, http.StatusOK, viewerLogout.Code)

	// 6. Unified Policies endpoint
	policiesGet := dispatch(http.MethodGet, "/.raiwall/api/v1/policies", nil, adminCookie)
	require.Equal(t, http.StatusOK, policiesGet.Code)
	var policyData struct {
		RateLimits []any `json:"rate_limits"`
		BotDefense any   `json:"bot_defense"`
	}
	err = json.NewDecoder(policiesGet.Body).Decode(&policyData)
	require.NoError(t, err)

	// Update unified policies
	policiesPut := dispatch(http.MethodPut, "/.raiwall/api/v1/policies", map[string]any{
		"bot_defense": map[string]any{
			"host":           "*",
			"pow_enabled":    true,
			"pow_difficulty": 5,
		},
	}, adminCookie)
	require.Equal(t, http.StatusOK, policiesPut.Code)

	// 7. Cluster Status endpoint
	clusterRec := dispatch(http.MethodGet, "/.raiwall/api/v1/cluster/status", nil, adminCookie)
	require.Equal(t, http.StatusOK, clusterRec.Code)
	var clusterData struct {
		Mode           string `json:"mode"`
		RedisConnected bool   `json:"redis_connected"`
	}
	err = json.NewDecoder(clusterRec.Body).Decode(&clusterData)
	require.NoError(t, err)
	require.Equal(t, "standalone", clusterData.Mode)
	require.False(t, clusterData.RedisConnected)

	// 8. MCP Protocol over Middleware
	// MCP Tools List via JSON-RPC
	mcpListReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}
	mcpListRec := dispatch(http.MethodPost, "/.raiwall/api/mcp/message", mcpListReq, adminCookie)
	require.Equal(t, http.StatusOK, mcpListRec.Code)
	var mcpListResp mcp.JSONRPCResponse
	err = json.NewDecoder(mcpListRec.Body).Decode(&mcpListResp)
	require.NoError(t, err)
	require.Nil(t, mcpListResp.Error)
	require.NotNil(t, mcpListResp.Result)

	// Admin executes get_waf_status tool
	paramsJSON, _ := json.Marshal(map[string]any{
		"name":      "get_waf_status",
		"arguments": map[string]any{},
	})
	mcpCallReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params:  paramsJSON,
	}
	mcpCallRec := dispatch(http.MethodPost, "/.raiwall/api/mcp/message", mcpCallReq, adminCookie)
	require.Equal(t, http.StatusOK, mcpCallRec.Code)
	var mcpCallResp mcp.JSONRPCResponse
	err = json.NewDecoder(mcpCallRec.Body).Decode(&mcpCallResp)
	require.NoError(t, err)
	require.Nil(t, mcpCallResp.Error)
	require.NotNil(t, mcpCallResp.Result)

	// Login viewer again to test MCP role restrictions
	viewerLoginRec2 := dispatch(http.MethodPost, "/.raiwall/api/v1/auth/login", map[string]string{
		"username": "mw_viewer",
		"password": "viewerpass",
	}, nil)
	var viewerCookie2 *http.Cookie
	for _, c := range viewerLoginRec2.Result().Cookies() {
		if c.Name == "raiwall_session" {
			viewerCookie2 = c
			break
		}
	}
	require.NotNil(t, viewerCookie2)

	// Viewer executes mutating tool create_exception_rule -> should return JSON-RPC error
	mutatingParamsJSON, _ := json.Marshal(map[string]any{
		"name": "create_exception_rule",
		"arguments": map[string]any{
			"param_name": "unauthorized_exc",
		},
	})
	mcpMutatingReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  mutatingParamsJSON,
	}
	mcpMutatingRec := dispatch(http.MethodPost, "/.raiwall/api/mcp/message", mcpMutatingReq, viewerCookie2)
	require.Equal(t, http.StatusOK, mcpMutatingRec.Code)
	var mcpMutatingResp mcp.JSONRPCResponse
	err = json.NewDecoder(mcpMutatingRec.Body).Decode(&mcpMutatingResp)
	require.NoError(t, err)
	require.NotNil(t, mcpMutatingResp.Error)
	require.Equal(t, -32603, mcpMutatingResp.Error.Code)
	require.Contains(t, mcpMutatingResp.Error.Message, "not authorized to execute mutating tool")
}
