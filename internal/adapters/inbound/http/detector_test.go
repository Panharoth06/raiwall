package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dbCreateViewerKeyForDetector(token string) control.ApiKeyRecord {
	return control.ApiKeyRecord{
		ID:        "viewer-key-detector",
		Name:      "Viewer",
		KeyHash:   HashAPIKey(token),
		Role:      RoleViewer,
		IsActive:  1,
		CreatedAt: time.Now().UTC(),
	}
}

func TestAPI_SemanticDetectorMatrix(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_detector_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))
	// Seed a site for per-app policy tests
	appID := uuid.New().String()
	require.NoError(t, store.CreateApp(t.Context(), control.SiteApp{
		ID:        appID,
		Name:      "detector-app",
		Hostnames: `["detector.test"]`,
		Mode:      "defense",
		Upstreams: `[{"dial":"127.0.0.1:9100"}]`,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	// 1. GET detector: 14 modules listed, default mode "balance"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/detector", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var payload struct {
		Modules []struct {
			Module string `json:"module"`
			Mode   string `json:"mode"`
			Name   string `json:"name"`
		} `json:"modules"`
		Apps []detectorAppPolicyDTO `json:"apps"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	require.Len(t, payload.Modules, 14)
	for _, m := range payload.Modules {
		assert.Equal(t, "balance", m.Mode)
		assert.NotEmpty(t, m.Name)
	}
	assert.Empty(t, payload.Apps)

	// 2. PUT module mode (sql_inj -> strict)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/detector/modules/sql_inj",
		bytes.NewReader([]byte(`{"mode":"strict"}`)))
	put.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, put)
	require.Equal(t, http.StatusOK, w.Code)

	// Verify persisted
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	for _, m := range payload.Modules {
		if m.Module == "sql_inj" {
			assert.Equal(t, "strict", m.Mode)
		}
	}

	// 3. Unknown module -> 400
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detector/modules/nonsense",
		bytes.NewReader([]byte(`{"mode":"strict"}`)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 4. Invalid mode -> 400
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detector/modules/sql_inj",
		bytes.NewReader([]byte(`{"mode":"paranoid"}`)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 5. Per-app override (xss -> disabled, ssti -> strict)
	appPut := httptest.NewRequest(http.MethodPut, "/api/v1/detector/apps/"+appID,
		bytes.NewReader([]byte(`{"overrides":{"xss":"disabled","ssti":"strict"}}`)))
	appPut.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, appPut)
	require.Equal(t, http.StatusOK, w.Code)

	// 6. GET detector apps list includes the app
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	require.Len(t, payload.Apps, 1)
	assert.Equal(t, appID, payload.Apps[0].AppID)
	assert.Equal(t, "disabled", payload.Apps[0].Overrides["xss"])

	// 7. GET single-app policy
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector/apps/"+appID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var appPolicy detectorAppPolicyDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &appPolicy))
	assert.Equal(t, "strict", appPolicy.Overrides["ssti"])

	// 8. Clear per-app policy (empty overrides)
	appClear := httptest.NewRequest(http.MethodPut, "/api/v1/detector/apps/"+appID,
		bytes.NewReader([]byte(`{"overrides":{}}`)))
	appClear.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, appClear)
	require.Equal(t, http.StatusOK, w.Code)

	recsDebug, _ := store.ListAppSemanticPolicies(t.Context())
	require.Empty(t, recsDebug)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector/apps/"+appID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	appPolicy = detectorAppPolicyDTO{} // fresh struct: json v2 does not clear reused maps
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &appPolicy))
	assert.Empty(t, appPolicy.Overrides)

	// 9. Site not found -> 404
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detector/apps/ghost-app",
		bytes.NewReader([]byte(`{"overrides":{"xss":"disabled"}}`)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// 10. Viewer role cannot mutate (RBAC)
	viewerToken := "rw_viewer_detector_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateViewerKeyForDetector(viewerToken))
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detector/modules/sql_inj",
		bytes.NewReader([]byte(`{"mode":"audit"}`)))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// 11. Unauthenticated -> 401
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector", nil)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
