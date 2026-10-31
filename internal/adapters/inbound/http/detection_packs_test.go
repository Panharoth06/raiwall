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

func jsonBytes(value any) ([]byte, error) {
	return json.Marshal(value)
}

// resetGlobalSnapshot isolates detection tests from the process-wide snapshot.
func resetGlobalSnapshot(t *testing.T) {
	t.Helper()
	control.SetActiveSnapshot(nil)
	t.Cleanup(func() { control.SetActiveSnapshot(nil) })
}

func packPayload() map[string]any {
	return map[string]any{
		"name":     "Company Native Rules",
		"version":  "1.0.0",
		"type":     "native",
		"relation": "additive",
		"rules": []map[string]any{
			{
				"id":       "custom-1",
				"name":     "Block /evil",
				"category": "rce",
				"matches":  []map[string]any{{"field": "path", "token": "/evil"}},
			},
		},
	}
}

func TestAPI_DetectionPackLifecycle(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)
	ctx := t.Context()
	adminToken := "rw_admin_detection_packs"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	payload, err := jsonBytes(packPayload())
	require.NoError(t, err)

	// Dry-run validation never persists.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs/validate", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"valid":true`)
	require.Contains(t, w.Body.String(), `"rules_parsed":1`)
	if snap := control.GetActiveSnapshot(); snap != nil {
		require.Empty(t, snap.RulePacks)
	}

	// Install the pack; auto-apply compiles it into the snapshot.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	active := control.GetActiveSnapshot()
	require.Len(t, active.RulePacks, 1)
	packID := active.RulePacks[0].ID
	require.Equal(t, control.PackTypeNative, active.RulePacks[0].Type)
	require.True(t, active.RulePacks[0].Enabled)

	// Catalog exposes the imported rule under its namespaced canonical ID.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detection/rules?source=pack", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "pack:"+packID+":custom-1")

	// Disabling the pack removes its rules from enforcement.
	disabled, _ := jsonBytes(map[string]any{"enabled": false})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/detection/packs/"+packID, bytes.NewReader(disabled))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	active = control.GetActiveSnapshot()
	require.False(t, active.RulePacks[0].Enabled)

	// Delete removes the pack and its overrides.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/detection/packs/"+packID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	active = control.GetActiveSnapshot()
	require.Empty(t, active.RulePacks)
}

func TestAPI_ModsecurityPackLifecycle(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)
	ctx := t.Context()
	adminToken := "rw_admin_modsec_packs"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	payload, _ := jsonBytes(map[string]any{
		"name":       "Company ModSec Rules",
		"version":    "1.0.0",
		"type":       "modsec",
		"relation":   "additive",
		"directives": `SecRule REQUEST_URI "@contains /evil" "id:10001,phase:1,deny,status:403,msg:'custom block'"`,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs/validate", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"valid":true`)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	active := control.GetActiveSnapshot()
	require.Len(t, active.RulePacks, 1)
	require.Equal(t, control.PackTypeModsec, active.RulePacks[0].Type)
	packID := active.RulePacks[0].ID

	// The imported SecRule appears in the catalog with a namespaced ID.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detection/rules?source=pack&pack="+packID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "pack:"+packID+":10001")

	// A per-rule override is stored for the Coraza engine.
	body, _ := jsonBytes(map[string]any{"action": "alert"})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/detection/rules/pack:"+packID+":10001", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	active = control.GetActiveSnapshot()
	override := active.RuleOverrides["pack:"+packID+":10001"]
	require.NotNil(t, override)
	require.Equal(t, control.RuleActionAlert, override.Action)
}

func TestAPI_DetectionPackRejectsInvalidRules(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)
	ctx := t.Context()
	adminToken := "rw_admin_detection_pack_invalid"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	payload, _ := jsonBytes(map[string]any{
		"name":    "Broken Pack",
		"version": "1.0.0",
		"type":    "native",
		"rules":   []map[string]any{{"id": "bad", "name": "No matches"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs/validate", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"valid":false`)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/detection/packs", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	if snap := control.GetActiveSnapshot(); snap != nil {
		require.Empty(t, snap.RulePacks)
	}
}
