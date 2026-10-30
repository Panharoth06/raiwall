package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_DeclarativeResourceOverrideFlow(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	ctx := context.Background()
	adminToken := "rw_admin_override_token"
	_ = store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken))

	res := &config.DeclarativeResources{
		Mode: "sync",
		ACLs: []config.ACLRule{{
			Name:       "block_attack",
			Expression: "client_ip == '10.0.0.1'",
			Action:     "block",
			Priority:   50,
			StatusCode: 403,
		}},
		Templates: []config.Template{{
			StatusCode:  403,
			Title:       "Original Declarative 403",
			ContentHTML: "<h1>Forbidden</h1>",
		}},
	}

	// 1. Initial declarative sync materializes the resources
	syncRes, err := declarative.Sync(ctx, store, res)
	require.NoError(t, err)
	assert.Equal(t, 2, syncRes.Created)

	aclID := "cfg:acl:block_attack"
	tmplID := declarative.TemplateID(403)

	// 2. Mutate ACL rule through API: PUT /api/v1/acls/{id}
	// Previously this failed with 409 Conflict. Now it must succeed with 200 OK.
	updateACLPayload, _ := json.Marshal(map[string]any{
		"expression": "client_ip == '10.0.0.2'",
		"priority":   200,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/acls/"+aclID, bytes.NewReader(updateACLPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var updatedACL ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &updatedACL))
	assert.Equal(t, aclID, updatedACL.ID)
	assert.True(t, updatedACL.Managed)
	assert.Equal(t, "client_ip == '10.0.0.2'", updatedACL.Expression)
	assert.Equal(t, 200, updatedACL.Priority)

	// 3. Mutate Template through API: PUT /api/v1/templates/{statusCode}
	// Previously returned 409 Conflict. Now must succeed with 200 OK.
	updateTmplPayload, _ := json.Marshal(map[string]any{
		"title":        "Overridden Page",
		"content_html": "<h2>Access Denied</h2>",
	})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/templates/403", bytes.NewReader(updateTmplPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var updatedTmpl TemplateDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &updatedTmpl))
	assert.Equal(t, "Overridden Page", updatedTmpl.Title)

	// 4. Verify overrides set in store
	overrides := declarative.LoadOverrides(ctx, store)
	assert.Contains(t, overrides, aclID)
	assert.Contains(t, overrides, tmplID)

	// 5. Run declarative sync again with the original YAML
	// Overridden resources should be skipped, preserving operator edits.
	syncRes2, err := declarative.Sync(ctx, store, res)
	require.NoError(t, err)
	assert.Equal(t, 2, syncRes2.Skipped)
	assert.Equal(t, 0, syncRes2.Created+syncRes2.Updated+syncRes2.Deleted)

	ruleInStore, err := store.GetACLRule(ctx, aclID)
	require.NoError(t, err)
	assert.Equal(t, "client_ip == '10.0.0.2'", ruleInStore.Expression)
	assert.Equal(t, int64(200), ruleInStore.Priority)

	tmplInStore, err := store.GetTemplate(ctx, 403)
	require.NoError(t, err)
	assert.Equal(t, "Overridden Page", tmplInStore.Title)

	// 6. Delete the ACL rule via API: DELETE /api/v1/acls/{id}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/acls/"+aclID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Re-run sync: rule should remain deleted (not recreated) because it is overridden.
	_, err = declarative.Sync(ctx, store, res)
	require.NoError(t, err)
	assert.Contains(t, declarative.LoadOverrides(ctx, store), aclID)

	_, err = store.GetACLRule(ctx, aclID)
	require.Error(t, err, "deleted overridden rule must not be resurrected by declarative sync")
}
