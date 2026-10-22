//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	api "github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

type mockPublisher struct {
	mu        sync.Mutex
	published []uint64
}

func (m *mockPublisher) PublishVersion(ctx context.Context, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = append(m.published, version)
	return nil
}

func (m *mockPublisher) PublishBan(ctx context.Context, entry *rate.BanEntry) error {
	return nil
}

func (m *mockPublisher) PublishUnblock(ctx context.Context, target string) error {
	return nil
}

func (m *mockPublisher) PublishUnblockAll(ctx context.Context) error {
	return nil
}

func (m *mockPublisher) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.published)
}

func (m *mockPublisher) get(idx int) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < len(m.published) {
		return m.published[idx]
	}
	return 0
}

func TestControlPlane_E2E_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	dbDSN := fmt.Sprintf("file:test_e2e_cp_%d?mode=memory&cache=shared", time.Now().UnixNano())

	store, err := sqlite.InitDB(dbDSN)
	require.NoError(t, err)
	defer store.Close()
	defer control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))

	// 1. Create Admin User
	hash, err := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	now := time.Now().UTC()
	err = store.CreateUser(ctx, control.UserRecord{
		ID:           uuid.NewString(),
		Username:     "admin_e2e",
		PasswordHash: string(hash),
		Role:         "admin",
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	// 2. Initialize API Server
	apiServer := api.NewServer(store, []byte("e2e_test_secret_32_bytes_long_ok"))
	pub := &mockPublisher{}
	apiServer.SetClusterPublisher(pub)
	router := apiServer.Router()

	doRequest := func(method, path string, payload any, cookie *http.Cookie) *httptest.ResponseRecorder {
		var bodyReader *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			bodyReader = bytes.NewReader(b)
		} else {
			bodyReader = bytes.NewReader([]byte{})
		}
		req := httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// 3. Test Unauthenticated Requests get 401
	unauthRec := doRequest(http.MethodGet, "/.raiwall/api/v1/sites", nil, nil)
	require.Equal(t, http.StatusUnauthorized, unauthRec.Code)

	// 4. Test Login
	loginPayload := map[string]string{
		"username": "admin_e2e",
		"password": "adminpass123",
	}
	loginRec := doRequest(http.MethodPost, "/.raiwall/api/v1/auth/login", loginPayload, nil)
	require.Equal(t, http.StatusOK, loginRec.Code)

	var authCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "raiwall_session" {
			authCookie = c
			break
		}
	}
	require.NotNil(t, authCookie, "expected session cookie to be set")

	doAuth := func(method, path string, payload any) *httptest.ResponseRecorder {
		return doRequest(method, path, payload, authCookie)
	}

	// 5. Test Site Lifecycle
	createSitePayload := map[string]any{
		"name":           "Primary App",
		"hostnames":      []string{"app.example.com", "api.example.com"},
		"upstream_addrs": []string{"10.0.0.1:8080", "10.0.0.2:8080"},
		"mode":           "defense",
	}
	siteRec := doAuth(http.MethodPost, "/.raiwall/api/v1/sites", createSitePayload)
	require.Equal(t, http.StatusCreated, siteRec.Code)

	var createdSite struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(siteRec.Body).Decode(&createdSite)
	require.NoError(t, err)
	siteID := createdSite.ID
	require.NotEmpty(t, siteID)

	// 6. Test Exception Rule Lifecycle
	createExcPayload := map[string]any{
		"site_id":     siteID,
		"rule_id":     "SEMANTIC_SQLI",
		"param_name":  "search_term",
		"location":    "query",
		"path_prefix": "/search",
		"description": "Bypass search input",
	}
	excRec := doAuth(http.MethodPost, "/.raiwall/api/v1/exceptions", createExcPayload)
	require.Equal(t, http.StatusCreated, excRec.Code)

	// 7. Test ACL Rule Lifecycle
	createACLPayload := map[string]any{
		"site_id":     siteID,
		"name":        "Block Internal",
		"expression":  `has_prefix(path, "/internal") && client_ip != "127.0.0.1"`,
		"action":      "block",
		"status_code": 403,
		"priority":    10,
	}
	aclRec := doAuth(http.MethodPost, "/.raiwall/api/v1/acls", createACLPayload)
	require.Equal(t, http.StatusCreated, aclRec.Code)

	// 8. Apply Configuration (Compiles into snapshot version 1)
	applyRec1 := doAuth(http.MethodPost, "/.raiwall/api/v1/config/apply", map[string]string{
		"description": "Initial setup",
	})
	require.Equal(t, http.StatusOK, applyRec1.Code)

	activeSnap1 := control.GetActiveSnapshot()
	require.NotNil(t, activeSnap1)
	require.Equal(t, uint64(1), activeSnap1.Version)
	require.Len(t, activeSnap1.Apps, 1)
	require.Len(t, activeSnap1.Exceptions, 1)
	require.Len(t, activeSnap1.ACLRules, 1)

	// Verify publisher was notified
	require.Eventually(t, func() bool { return pub.count() >= 1 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), pub.get(0))

	// 9. Modify and apply snapshot version 2
	updateSitePayload := map[string]any{
		"name":           "Primary App Updated",
		"hostnames":      []string{"app.example.com"},
		"upstream_addrs": []string{"10.0.0.1:8080"},
		"mode":           "audit",
	}
	updateSiteRec := doAuth(http.MethodPut, fmt.Sprintf("/.raiwall/api/v1/sites/%s", siteID), updateSitePayload)
	require.Equal(t, http.StatusOK, updateSiteRec.Code)

	applyRec2 := doAuth(http.MethodPost, "/.raiwall/api/v1/config/apply", map[string]string{
		"description": "Updated mode to audit",
	})
	require.Equal(t, http.StatusOK, applyRec2.Code)
	activeSnap2 := control.GetActiveSnapshot()
	require.Equal(t, uint64(2), activeSnap2.Version)
	require.Eventually(t, func() bool { return pub.count() >= 2 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(2), pub.get(1))

	// 10. 1-Click Rollback to version 1
	rollbackRec := doAuth(http.MethodPost, "/.raiwall/api/v1/config/rollback/1", nil)
	require.Equal(t, http.StatusOK, rollbackRec.Code)

	revertedSnap := control.GetActiveSnapshot()
	require.Equal(t, uint64(1), revertedSnap.Version)
	require.Eventually(t, func() bool { return pub.count() >= 3 }, 1*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), pub.get(2))

	// 11. Test HTTP Basic Auth
	basicAuthReq := httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/sites", nil)
	basicAuthReq.SetBasicAuth("admin_e2e", "adminpass123")
	basicAuthRec := httptest.NewRecorder()
	router.ServeHTTP(basicAuthRec, basicAuthReq)
	require.Equal(t, http.StatusOK, basicAuthRec.Code, "valid basic auth should return 200")

	badBasicReq := httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/sites", nil)
	badBasicReq.SetBasicAuth("admin_e2e", "wrongpassword")
	badBasicRec := httptest.NewRecorder()
	router.ServeHTTP(badBasicRec, badBasicReq)
	require.Equal(t, http.StatusUnauthorized, badBasicRec.Code, "invalid basic auth should return 401")

	// 12. Test Named IP Groups API Lifecycle (Task 94)
	createIPGPayload := map[string]string{
		"name":        "e2e_ip_group",
		"description": "Integration test IP group",
		"type":        "custom",
	}
	ipgCreateRec := doAuth(http.MethodPost, "/.raiwall/api/v1/ip-groups", createIPGPayload)
	require.Equal(t, http.StatusCreated, ipgCreateRec.Code)
	var createdIPG struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	err = json.NewDecoder(ipgCreateRec.Body).Decode(&createdIPG)
	require.NoError(t, err)
	require.NotEmpty(t, createdIPG.ID)
	require.Equal(t, "e2e_ip_group", createdIPG.Name)

	// List IP groups
	ipgListRec := doAuth(http.MethodGet, "/.raiwall/api/v1/ip-groups", nil)
	require.Equal(t, http.StatusOK, ipgListRec.Code)

	// Add entry to IP group
	addEntryPayload := map[string]string{
		"cidr":    "192.0.2.0/24",
		"comment": "RFC 5737 Test Subnet",
	}
	addEntryRec := doAuth(http.MethodPost, fmt.Sprintf("/.raiwall/api/v1/ip-groups/%s/entries", createdIPG.ID), addEntryPayload)
	require.Equal(t, http.StatusCreated, addEntryRec.Code)
	var createdEntry struct {
		ID   string `json:"id"`
		CIDR string `json:"cidr"`
	}
	err = json.NewDecoder(addEntryRec.Body).Decode(&createdEntry)
	require.NoError(t, err)
	require.NotEmpty(t, createdEntry.ID)

	// Get group details
	ipgGetRec := doAuth(http.MethodGet, fmt.Sprintf("/.raiwall/api/v1/ip-groups/%s", createdIPG.ID), nil)
	require.Equal(t, http.StatusOK, ipgGetRec.Code)

	// Delete entry
	delEntryRec := doAuth(http.MethodDelete, fmt.Sprintf("/.raiwall/api/v1/ip-groups/%s/entries/%s", createdIPG.ID, createdEntry.ID), nil)
	require.Equal(t, http.StatusOK, delEntryRec.Code)

	// Delete group
	delGroupRec := doAuth(http.MethodDelete, fmt.Sprintf("/.raiwall/api/v1/ip-groups/%s", createdIPG.ID), nil)
	require.Equal(t, http.StatusOK, delGroupRec.Code)

	// 13. Test Custom Response Templates API Lifecycle (Task 95)
	tmplsListRec := doAuth(http.MethodGet, "/.raiwall/api/v1/templates", nil)
	require.Equal(t, http.StatusOK, tmplsListRec.Code)

	tmpl403Rec := doAuth(http.MethodGet, "/.raiwall/api/v1/templates/403", nil)
	require.Equal(t, http.StatusOK, tmpl403Rec.Code)

	updateTmplPayload := map[string]string{
		"title":        "Corporate Block",
		"content_html": "<h1>Security Warning</h1><p>{{.EventID}}</p>",
		"custom_css":   "h1 { color: #f00; }",
		"brand_name":   "Enterprise Shield",
	}
	updateTmplRec := doAuth(http.MethodPut, "/.raiwall/api/v1/templates/403", updateTmplPayload)
	require.Equal(t, http.StatusOK, updateTmplRec.Code)

	previewPayload := map[string]string{
		"content_html": "<h1>Preview Warning</h1>",
		"brand_name":   "Enterprise Shield",
	}
	previewRec := doAuth(http.MethodPost, "/.raiwall/api/v1/templates/403/preview", previewPayload)
	require.Equal(t, http.StatusOK, previewRec.Code)

	resetRec := doAuth(http.MethodPost, "/.raiwall/api/v1/templates/403/reset", nil)
	require.Equal(t, http.StatusOK, resetRec.Code)
}
