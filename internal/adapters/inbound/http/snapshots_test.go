package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestAPI_DraftDiffApplyAndRollback(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	ctx := t.Context()
	adminToken := "rw_admin_snap_token"
	_ = store.CreateAPIKey(ctx, dbCreateAdminKey(adminToken))

	// Initial active snapshot with 0 apps
	baseSnap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	control.StoreSnapshot(baseSnap)

	// 1. Create site in SQLite draft
	now := time.Now().UTC()
	err := store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "site-shop",
		Name:                "E-Commerce Shop",
		Hostnames:           `["shop.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"127.0.0.1:4000"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	require.NoError(t, err)

	// 2. GET /api/v1/config/draft/diff should detect staged additions
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/draft/diff", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var diffRes ConfigDiffResponse
	err = json.Unmarshal(w.Body.Bytes(), &diffRes)
	require.NoError(t, err)
	require.True(t, diffRes.HasChanges)
	require.NotEmpty(t, diffRes.Added)

	// 3. POST /api/v1/config/apply should commit revision 1 and swap pointer
	applyBody, _ := json.Marshal(ApplyRequest{
		Author:      "devops",
		Description: "Initial shop deployment",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/config/apply", bytes.NewReader(applyBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var applyRes ApplyResponse
	err = json.Unmarshal(w.Body.Bytes(), &applyRes)
	require.NoError(t, err)
	require.True(t, applyRes.Success)
	require.Equal(t, uint64(1), applyRes.Version)

	// Verify active snapshot now has site-shop
	active := control.GetActiveSnapshot()
	require.Equal(t, uint64(1), active.Version)
	_, found := active.GetAppForHost("shop.example.com")
	require.True(t, found)

	// 4. Add second site in draft
	err = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:                  "site-admin-portal",
		Name:                "Admin Portal",
		Hostnames:           `["portal.example.com"]`,
		Mode:                "defense",
		Upstreams:           `[{"dial":"127.0.0.1:5000"}]`,
		BlockStatusCode:     403,
		BlockResponseBody:   "",
		OfflineStatusCode:   503,
		OfflineResponseBody: "",
		CustomHeaders:       "{}",
		CreatedAt:           now.Add(time.Minute),
		UpdatedAt:           now.Add(time.Minute),
	})
	require.NoError(t, err)

	// Apply revision 2
	applyBody, _ = json.Marshal(ApplyRequest{
		Author:      "devops",
		Description: "Added admin portal",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/config/apply", bytes.NewReader(applyBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	active = control.GetActiveSnapshot()
	require.Equal(t, uint64(2), active.Version)
	require.Len(t, active.Apps, 2)

	// 5. POST /api/v1/config/rollback/1 reverts to revision 1
	req = httptest.NewRequest(http.MethodPost, "/api/v1/config/rollback/1", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	active = control.GetActiveSnapshot()
	require.Equal(t, uint64(1), active.Version)
	require.Len(t, active.Apps, 1)
	_, found = active.GetAppForHost("portal.example.com")
	require.False(t, found)
	_, found = active.GetAppForHost("shop.example.com")
	require.True(t, found)
}
