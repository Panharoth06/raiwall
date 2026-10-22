package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_IPGroupsCRUDAndDynamicBART(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	// Initialize IPGroupManager on server
	bt := acl.NewBARTTable()
	ipGroupMgr := acl.NewIPGroupManager(bt)
	server.SetIPGroupManager(ipGroupMgr)

	adminToken := "rw_admin_ipgroups_token"
	_ = store.CreateAPIKey(t.Context(), dbCreateAdminKey(adminToken))

	// 1. Create IP Group
	createPayload, _ := json.Marshal(map[string]string{
		"name":        "corporate_vpn",
		"description": "Office VPN gateways",
		"type":        "custom",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ip-groups", bytes.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created IPGroupDTO
	err := json.Unmarshal(w.Body.Bytes(), &created)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "corporate_vpn", created.Name)

	// 2. Add CIDR entry ("Add to IP Group" API)
	entryPayload, _ := json.Marshal(map[string]string{
		"cidr":    "203.0.113.0/24",
		"comment": "HQ Office Exit Node",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ip-groups/"+created.ID+"/entries", bytes.NewReader(entryPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var entry IPGroupEntryDTO
	err = json.Unmarshal(w.Body.Bytes(), &entry)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.0/24", entry.CIDR)

	// 3. Verify in-memory BART table was updated dynamically
	assert.True(t, ipGroupMgr.InGroupStr("203.0.113.50", "corporate_vpn"))
	assert.False(t, ipGroupMgr.InGroupStr("8.8.8.8", "corporate_vpn"))

	// 4. Get IP Group with entries
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ip-groups/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var fetched IPGroupDTO
	err = json.Unmarshal(w.Body.Bytes(), &fetched)
	require.NoError(t, err)
	assert.Equal(t, 1, fetched.EntryCount)
	require.Len(t, fetched.Entries, 1)
	assert.Equal(t, "203.0.113.0/24", fetched.Entries[0].CIDR)

	// 5. Delete Entry
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/ip-groups/"+created.ID+"/entries/"+entry.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Verify dynamically removed from BART table
	assert.False(t, ipGroupMgr.InGroupStr("203.0.113.50", "corporate_vpn"))

	// 6. Delete Group
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/ip-groups/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 7. Verify group is gone
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ip-groups/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}
