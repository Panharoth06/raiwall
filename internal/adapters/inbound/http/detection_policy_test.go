package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestAPI_DetectionPolicyLifecycle(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)

	ctx := t.Context()
	adminToken := "rw_admin_detection_policy"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))
	viewerToken := "rw_viewer_detection_policy"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateViewerKeyForDetector(viewerToken)))

	payload := map[string]any{
		"detection_mode":     "alert",
		"sensitivity":        "high",
		"semantic_overrides": map[string]string{"xss": "strict"},
		"crs": map[string]any{
			"enabled":            true,
			"paranoia_level":     2,
			"inbound_threshold":  3,
			"outbound_threshold": 2,
		},
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/detection/policy", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, w.Header().Get("X-Raiwall-Config-Version"))

	active := control.GetActiveSnapshot()
	require.NotNil(t, active.WAFPolicy)
	require.Equal(t, control.DetectionModeAlert, active.WAFPolicy.DetectionMode)
	require.Equal(t, control.SensitivityHigh, active.WAFPolicy.Sensitivity)
	require.NotNil(t, active.WAFPolicy.CRSEnabled)
	require.True(t, *active.WAFPolicy.CRSEnabled)
	require.Equal(t, waf.ModeStrict, active.SemanticMatrixFor("").Mode(waf.ModuleXSS))

	// Status reflects the applied policy.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detection/status", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var status detectionStatusDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	require.Equal(t, control.DetectionModeAlert, status.DetectionMode)
	require.Equal(t, control.SensitivityHigh, status.Sensitivity)
	require.True(t, status.CRSEnabled)

	// GET returns the stored policy DTO.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detection/policy", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var policyResponse map[string]wafPolicyDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &policyResponse))
	require.Equal(t, control.DetectionModeAlert, policyResponse["policy"].DetectionMode)
	require.Equal(t, "strict", policyResponse["policy"].SemanticOverrides["xss"])

	// Invalid mode is rejected.
	badPayload, _ := json.Marshal(map[string]any{"detection_mode": "turbo", "sensitivity": "medium"})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detection/policy", bytes.NewReader(badPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	// Viewers cannot mutate policies.
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detection/policy", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestAPI_AppDetectionPolicyLifecycle(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)

	ctx := t.Context()
	adminToken := "rw_admin_app_detection_policy"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	now := time.Now().UTC()
	require.NoError(t, store.CreateApp(ctx, control.SiteApp{
		ID:        "app-policy",
		Name:      "Policy App",
		Hostnames: `["policy.test"]`,
		Mode:      "defense",
		Upstreams: `[{"dial":"127.0.0.1:9000"}]`,
		CreatedAt: now,
		UpdatedAt: now,
	}))
	_, err := control.DeploySnapshot(ctx, store, "test", "initial")
	require.NoError(t, err)

	payload, _ := json.Marshal(map[string]any{
		"detection_mode": "off",
		"sensitivity":    "medium",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/detection/policies/apps/app-policy", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	active := control.GetActiveSnapshot()
	require.NotNil(t, active.Apps["app-policy"].WAFPolicy)
	require.Equal(t, control.DetectionModeOff, active.ResolveWAFPolicyFor("app-policy").DetectionMode)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/detection/policies/apps/app-policy", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"detection_mode":"off"`)

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/detection/policies/apps/app-policy", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	active = control.GetActiveSnapshot()
	require.Nil(t, active.Apps["app-policy"].WAFPolicy)
}
