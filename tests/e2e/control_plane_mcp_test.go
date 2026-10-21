//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestControlPlane_E2E_ProxyMiddlewareAndMCP(t *testing.T) {
	ctx := context.Background()
	dbDSN := fmt.Sprintf("file:test_e2e_proxy_cp_%d?mode=memory&cache=shared", time.Now().UnixNano())

	// 1. Initialize Middleware with Control Plane configuration
	mw := &caddy.Middleware{
		Mode: "defense",
		ControlConfig: &caddy.ControlSettings{
			DBPath:     dbDSN,
			HMACSecret: "e2e_test_secret_32_bytes_long_ok",
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: ctx})
	defer cancel()

	err := mw.Provision(caddyCtx)
	require.NoError(t, err)
	defer mw.Cleanup()
	defer control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))

	store := mw.ControlAPI().Store()
	require.NotNil(t, store)

	// Create admin and viewer users
	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminpass"), bcrypt.DefaultCost)
	require.NoError(t, err)
	viewerHash, err := bcrypt.GenerateFromPassword([]byte("viewerpass"), bcrypt.DefaultCost)
	require.NoError(t, err)

	now := time.Now().UTC()
	err = store.CreateUser(ctx, control.UserRecord{
		ID:           uuid.NewString(),
		Username:     "mw_admin",
		PasswordHash: string(adminHash),
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	err = store.CreateUser(ctx, control.UserRecord{
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
