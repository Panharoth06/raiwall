package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestAPI_DetectionRuleCatalogAndOverrides(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)

	ctx := t.Context()
	adminToken := "rw_admin_rule_catalog"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	// Catalog listing returns bundled CVE + semantic rows with facets.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/detection/rules?source=cve&limit=5&q=CVE-2021-44228", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"rules"`)
	require.Contains(t, w.Body.String(), `"facets"`)
	require.Contains(t, w.Body.String(), "CVE-2021-44228")

	// Disable a bundled virtual patch; the snapshot must carry the override.
	body, _ := jsonBytes(map[string]any{"enabled": false})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/detection/rules/cve:CVE-2021-44228", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	active := control.GetActiveSnapshot()
	require.Contains(t, active.InnerRulesDisabled, "CVE-2021-44228")
	require.NotNil(t, active.RuleOverrides["cve:CVE-2021-44228"])

	// Semantic modules map action overrides onto the detector matrix.
	body, _ = jsonBytes(map[string]any{"action": "off"})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/detection/rules/semantic:sql_inj", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	active = control.GetActiveSnapshot()
	require.Equal(t, waf.ModeDisabled, active.SemanticDefaults[waf.ModuleSQLInj])

	// Reset restores the default matrix and clears the CVE override.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/detection/rules/semantic:sql_inj/override", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	active = control.GetActiveSnapshot()
	require.Equal(t, waf.ModeBalance, active.SemanticMatrixFor("").Mode(waf.ModuleSQLInj))

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/detection/rules/cve:CVE-2021-44228/override", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	active = control.GetActiveSnapshot()
	require.NotContains(t, active.InnerRulesDisabled, "CVE-2021-44228")
}

func TestAPI_DetectionRuleValidation(t *testing.T) {
	resetGlobalSnapshot(t)
	server, store := setupTestServer(t)
	defer store.Close()
	server.SetAutoApply(true)
	ctx := t.Context()
	adminToken := "rw_admin_rule_validation"
	require.NoError(t, store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken)))

	body, _ := jsonBytes(map[string]any{"action": "turbo"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/detection/rules/cve:CVE-2021-44228", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/detection/rules/cve:DOES-NOT-EXIST", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)

	// Bulk overrides apply to every requested rule.
	body, _ = jsonBytes(map[string]any{
		"ids":     []string{"semantic:xss", "semantic:ssti"},
		"enabled": false,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/detection/rules/bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"updated":2`)

	active := control.GetActiveSnapshot()
	require.Equal(t, waf.ModeDisabled, active.SemanticDefaults[waf.ModuleXSS])
	require.Equal(t, waf.ModeDisabled, active.SemanticDefaults[waf.ModuleSSTI])
}
