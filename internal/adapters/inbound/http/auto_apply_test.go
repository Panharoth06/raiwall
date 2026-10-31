package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func resetActiveSnapshot(t *testing.T) {
	t.Helper()
	control.SetActiveSnapshot(nil)
	t.Cleanup(func() { control.SetActiveSnapshot(nil) })
}

func TestAutoApply_CommitsSnapshotAfterMutation(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	resetActiveSnapshot(t)
	server.SetAutoApply(true)

	adminToken := "rw_admin_auto_apply"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	payload, _ := json.Marshal(SiteDTO{
		Name:      "Auto Applied",
		Hostnames: []string{"auto.example.com"},
		Mode:      "defense",
		Upstreams: []control.UpstreamTarget{{Dial: "127.0.0.1:3000", Weight: 1}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, "1", w.Header().Get("X-Raiwall-Config-Version"))

	active := control.GetActiveSnapshot()
	require.NotNil(t, active)
	require.Equal(t, uint64(1), active.Version)
	_, found := active.GetAppForHost("auto.example.com")
	require.True(t, found)

	history, err := control.ListSnapshotHistory(t.Context(), store)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, "Admin", history[0].Author)
	require.Contains(t, history[0].Description, "POST /api/v1/sites")
}

func TestAutoApply_DisabledLeavesChangesStaged(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	resetActiveSnapshot(t)

	adminToken := "rw_admin_manual_apply"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	payload, _ := json.Marshal(SiteDTO{
		Name:      "Manual Apply",
		Hostnames: []string{"manual.example.com"},
		Mode:      "defense",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.Empty(t, w.Header().Get("X-Raiwall-Config-Version"))
	require.Nil(t, control.GetActiveSnapshot())

	history, err := control.ListSnapshotHistory(t.Context(), store)
	require.NoError(t, err)
	require.Empty(t, history)
}

func TestAutoApply_SimulationRoutesDoNotDeploy(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	resetActiveSnapshot(t)
	server.SetAutoApply(true)

	adminToken := "rw_admin_auto_apply_test_endpoint"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	payload, _ := json.Marshal(map[string]any{
		"expression":     `in_cidr(client_ip, "10.0.0.0/8")`,
		"sample_request": map[string]any{"client_ip": "10.1.2.3", "path": "/api"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acls/test", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Header().Get("X-Raiwall-Config-Version"))
	require.Nil(t, control.GetActiveSnapshot())
}

func TestAutoApply_FailedCompileReturnsError(t *testing.T) {
	server := &Server{autoApply: true}
	handler := server.AutoApplyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"saved":true}`))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "failed to apply")
	require.NotContains(t, w.Body.String(), `"saved":true`)
}

func TestIsSnapshotMutation(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/api/v1/sites", true},
		{http.MethodPut, "/.raiwall/api/v1/sites/site-1", true},
		{http.MethodPost, "/api/v1/sites/site-1/forwarding-rules", true},
		{http.MethodDelete, "/api/v1/sites/site-1/resources/res-1", false},
		{http.MethodPut, "/api/v1/sites/resources", true},
		{http.MethodPost, "/api/v1/exceptions", true},
		{http.MethodPost, "/api/v1/exceptions/test", false},
		{http.MethodPost, "/api/v1/exceptions/dry-run", false},
		{http.MethodPut, "/api/v1/exceptions/test-1", true},
		{http.MethodPost, "/.raiwall/api/v1/acls/test", false},
		{http.MethodPatch, "/api/v1/policies/rate/policy-1", true},
		{http.MethodPut, "/api/v1/detector/modules/sqli", true},
		{http.MethodPut, "/api/v1/inner-rules/rule-1", true},
		{http.MethodPost, "/api/v1/config/apply", false},
		{http.MethodPost, "/api/v1/rate/bans/release", false},
		{http.MethodPost, "/api/v1/apikeys", false},
		{http.MethodPost, "/api/v1/identity/users", false},
		{http.MethodPost, "/api/v1/templates/403/reset", false},
		{http.MethodGet, "/api/v1/sites", false},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, isSnapshotMutation(tt.method, tt.path))
		})
	}
}
