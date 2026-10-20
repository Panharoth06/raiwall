package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestAPI_SitesAndExceptionsCRUD(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_site_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	// 1. Create Site
	sitePayload, _ := json.Marshal(SiteDTO{
		Name:      "Blog Portal",
		Hostnames: []string{"blog.example.com"},
		Mode:      "defense",
		Upstreams: []control.UpstreamTarget{
			{Dial: "127.0.0.1:3000", Weight: 1},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", bytes.NewReader(sitePayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created SiteDTO
	err := json.Unmarshal(w.Body.Bytes(), &created)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	require.Equal(t, "Blog Portal", created.Name)

	// 2. Get Site
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sites/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 3. Create Exception
	excPayload, _ := json.Marshal(ExceptionDTO{
		Description: "Allow query param in blog search",
		Host:        "blog.example.com",
		PathRegex:   "^/search",
		Method:      "GET",
		Location:    "Query",
		ParamName:   "q",
		RuleID:      "SEMANTIC_SQLI",
		IsActive:    true,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/exceptions", bytes.NewReader(excPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var createdExc ExceptionDTO
	_ = json.Unmarshal(w.Body.Bytes(), &createdExc)
	require.NotEmpty(t, createdExc.ID)

	// 4. Test Exception Dry-Run Simulator
	testPayload, _ := json.Marshal(ExceptionTestRequest{
		Rule: createdExc,
		SampleRequest: ExceptionSampleRequest{
			Host:      "blog.example.com",
			Path:      "/search",
			Method:    "GET",
			Location:  "Query",
			ParamName: "q",
			RuleID:    "SEMANTIC_SQLI",
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/exceptions/test", bytes.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var testRes ExceptionTestResponse
	_ = json.Unmarshal(w.Body.Bytes(), &testRes)
	require.True(t, testRes.Matched)
}

func TestAPI_ACLAndExprDryRun(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_acl_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	// 1. Valid Expr Test
	testPayload, _ := json.Marshal(map[string]any{
		"expression": `in_cidr(client_ip, "10.0.0.0/8")`,
		"sample_request": map[string]any{
			"client_ip": "10.1.2.3",
			"path":      "/api",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acls/test", bytes.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var res ACLTestResponse
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	require.True(t, res.Valid)
	require.True(t, res.Matched)

	// 2. Invalid Expr Syntax Test
	badPayload, _ := json.Marshal(map[string]any{
		"expression": `not a valid expr ((+))`,
		"sample_request": map[string]any{
			"client_ip": "1.2.3.4",
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/acls/test", bytes.NewReader(badPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	_ = json.Unmarshal(w.Body.Bytes(), &res)
	require.False(t, res.Valid)
	require.NotEmpty(t, res.Error)
}

func dbCreateAdminKey(token string) sqlite.CreateAPIKeyParams {
	return sqlite.CreateAPIKeyParams{
		ID:        "admin-key",
		Name:      "Admin",
		KeyHash:   HashAPIKey(token),
		Role:      RoleAdmin,
		IsActive:  1,
		CreatedAt: tNow(),
	}
}

func tNow() time.Time {
	return time.Now().UTC()
}
