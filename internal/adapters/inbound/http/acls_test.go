package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPI_ACLRulesLifecycle(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	adminToken := "rw_admin_acl_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	// 1. Create ACL rule with continue_inspection = true
	createPayload, _ := json.Marshal(map[string]any{
		"name":                "Allow Office Subnet",
		"expression":          `in_cidr(client_ip, "192.168.1.0/24")`,
		"action":              "allow",
		"priority":            100,
		"enabled":             true,
		"continue_inspection": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acls", bytes.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.Equal(t, "Allow Office Subnet", created.Name)
	require.True(t, created.Enabled)
	require.True(t, created.IsActive)
	require.True(t, created.ContinueInspection)

	// 2. GET /acls/{id} and verify fields
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acls/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var fetched ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fetched))
	require.Equal(t, created.ID, fetched.ID)
	require.True(t, fetched.Enabled)
	require.True(t, fetched.IsActive)
	require.True(t, fetched.ContinueInspection)

	// 3. Toggle status to disable: PUT /acls/{id} with {"enabled": false} (partial update)
	togglePayload, _ := json.Marshal(map[string]any{
		"enabled": false,
	})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/acls/"+created.ID, bytes.NewReader(togglePayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var toggled ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &toggled))
	require.False(t, toggled.Enabled)
	require.False(t, toggled.IsActive)
	require.True(t, toggled.ContinueInspection)
	require.Equal(t, "Allow Office Subnet", toggled.Name)
	require.Equal(t, `in_cidr(client_ip, "192.168.1.0/24")`, toggled.Expression)

	// 4. Verify GET /acls lists the rule as disabled
	req = httptest.NewRequest(http.MethodGet, "/api/v1/acls", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var list []ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list, 1)
	require.False(t, list[0].Enabled)
	require.False(t, list[0].IsActive)
	require.True(t, list[0].ContinueInspection)

	// 5. Full update from Edit Modal: edit expression, priority, disable continue_inspection
	editPayload, _ := json.Marshal(map[string]any{
		"name":                "Allow Updated Office",
		"expression":          `in_cidr(client_ip, "10.0.0.0/8")`,
		"action":              "allow",
		"priority":            90,
		"enabled":             true,
		"continue_inspection": false,
	})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/acls/"+created.ID, bytes.NewReader(editPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var edited ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &edited))
	require.Equal(t, "Allow Updated Office", edited.Name)
	require.Equal(t, `in_cidr(client_ip, "10.0.0.0/8")`, edited.Expression)
	require.Equal(t, 90, edited.Priority)
	require.True(t, edited.Enabled)
	require.False(t, edited.ContinueInspection)

	// 6. Toggle continue_inspection back to true via partial update
	ciPayload, _ := json.Marshal(map[string]any{
		"continue_inspection": true,
	})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/acls/"+created.ID, bytes.NewReader(ciPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var ciUpdated ACLRuleDTO
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ciUpdated))
	require.True(t, ciUpdated.ContinueInspection)
	require.Equal(t, "Allow Updated Office", ciUpdated.Name)

	// 7. Delete ACL rule
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/acls/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}
