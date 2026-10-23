package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPI_InnerRulesLifecycle exercises the virtual-patch REST surface:
// GET list with category groups, single-rule toggle, category batch toggle,
// and 404 on unknown rule IDs.
func TestAPI_InnerRulesLifecycle(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_inner_rules_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/inner-rules", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var listResp struct {
		Rules []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Category string `json:"category"`
			Enabled  bool   `json:"enabled"`
		} `json:"rules"`
		Categories []struct {
			Category string `json:"category"`
			Count    int    `json:"count"`
			Disabled int    `json:"disabled"`
		} `json:"categories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))

	// 1. Bundled library loaded with every rule enabled by default
	require.NotEmpty(t, listResp.Rules)
	for _, rule := range listResp.Rules {
		assert.True(t, rule.Enabled, "rule %s should default to enabled", rule.ID)
	}
	// 2. Category groups present with counts matching rule distribution
	var rceCategory *struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
		Disabled int    `json:"disabled"`
	}
	categoryTotal := 0
	for i := range listResp.Categories {
		categoryTotal += listResp.Categories[i].Count
		if listResp.Categories[i].Category == "rce" {
			rceCategory = &listResp.Categories[i]
		}
	}
	require.NotNil(t, rceCategory)
	rceCount := rceCategory.Count
	require.Equal(t, len(listResp.Rules), categoryTotal)

	// 3. Disable one rule via PUT
	putBody, _ := json.Marshal(map[string]bool{"enabled": false})
	put := httptest.NewRequest(http.MethodPut, "/api/v1/inner-rules/CVE-2021-44228", bytes.NewReader(putBody))
	put.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, put)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 4. Re-list: the rule reports enabled=false and the rce category counts it
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))

	var log4shell *struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	for i := range listResp.Rules {
		if listResp.Rules[i].ID == "CVE-2021-44228" {
			log4shell = &listResp.Rules[i]
		}
	}
	require.NotNil(t, log4shell)
	assert.False(t, log4shell.Enabled, "disabled rule must report enabled=false")

	// 5. Unknown rule ID returns 404
	put = httptest.NewRequest(http.MethodPut, "/api/v1/inner-rules/NO-SUCH-RULE", bytes.NewReader(putBody))
	put.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, put)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// 6. Batch enable by category clears all rows in that category
	batchBody, _ := json.Marshal(map[string]bool{"enabled": false})
	batch := httptest.NewRequest(http.MethodPut, "/api/v1/inner-rules/categories/rce", bytes.NewReader(batchBody))
	batch.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, batch)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	for i := range listResp.Categories {
		if listResp.Categories[i].Category == "rce" {
			assert.Equal(t, rceCount, listResp.Categories[i].Count)
			assert.Equal(t, rceCount, listResp.Categories[i].Disabled)
		}
	}
	for _, rule := range listResp.Rules {
		if rule.Category == "rce" {
			assert.False(t, rule.Enabled, "rce rule %s should be disabled after batch", rule.ID)
		} else {
			assert.True(t, rule.Enabled, "non-rce rule %s must stay enabled", rule.ID)
		}
	}

	// 7. Batch enable-all for the category restores defaults
	batchBody, _ = json.Marshal(map[string]bool{"enabled": true})
	batch = httptest.NewRequest(http.MethodPut, "/api/v1/inner-rules/categories/rce", bytes.NewReader(batchBody))
	batch.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, batch)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	for _, rule := range listResp.Rules {
		assert.True(t, rule.Enabled, "rule %s should be re-enabled", rule.ID)
	}

	// 8. Unknown category is a 404
	batch = httptest.NewRequest(http.MethodPut, "/api/v1/inner-rules/categories/unknown-category", bytes.NewReader(batchBody))
	batch.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, batch)
	require.Equal(t, http.StatusNotFound, rec.Code)

	_ = control.ModeDefense // keep control import anchored for future assertions
}
