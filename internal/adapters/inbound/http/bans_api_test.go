package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/stretchr/testify/require"
)

type mockClusterPublisher struct {
	unblockCalled    string
	unblockAllCalled bool
}

func (m *mockClusterPublisher) PublishVersion(ctx context.Context, version uint64) error {
	return nil
}

func (m *mockClusterPublisher) PublishBan(ctx context.Context, entry *rate.BanEntry) error {
	return nil
}

func (m *mockClusterPublisher) PublishUnblock(ctx context.Context, target string) error {
	m.unblockCalled = target
	return nil
}

func (m *mockClusterPublisher) PublishUnblockAll(ctx context.Context) error {
	m.unblockAllCalled = true
	return nil
}

func TestBansAndWaitingRoomAPI(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Seed admin user and create auth cookie
	hash, err := HashPassword("AdminPass123!")
	require.NoError(t, err)

	err = store.CreateUser(ctx, sqlite.CreateUserParams{
		ID:           "u-admin-bans",
		Username:     "admin-bans",
		PasswordHash: hash,
		Role:         RoleAdmin,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)

	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin-bans",
		"password": "AdminPass123!",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	server.ServeHTTP(loginRec, loginReq)
	require.Equal(t, http.StatusOK, loginRec.Code)
	cookies := loginRec.Result().Cookies()
	require.NotEmpty(t, cookies)
	sessionCookie := cookies[0]

	// Configure BanManager and WaitingRoomManager on server
	bm := rate.NewBanManager(nil)
	defer bm.Close()
	server.SetBanManager(bm)

	wm := rate.NewWaitingRoomManager(rate.WaitingRoomConfig{
		MaxConcurrentInFlight: 10,
		MaxQueueDepth:         20,
		AdmissionRate:         5,
	})
	defer wm.Close()
	server.SetWaitingRoom(wm)

	pub := &mockClusterPublisher{}
	server.SetClusterPublisher(pub)

	// 1. Initially no bans
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rate/bans", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var bans []*rate.BanEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &bans))
	require.Empty(t, bans)

	// 2. Add active bans
	ip1 := net.ParseIP("198.51.100.101")
	ip2 := net.ParseIP("198.51.100.102")
	bm.Ban(ip1, "ja4_test_1", time.Hour, "tier1_velocity")
	bm.Ban(ip2, "", 2*time.Hour, "tier3_trap")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/rate/bans", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &bans))
	require.Len(t, bans, 2)
	require.Greater(t, bans[0].RemainingSeconds, int64(0))

	// 3. Release single ban
	releaseBody, _ := json.Marshal(map[string]string{
		"ip": "198.51.100.101",
	})
	relReq := httptest.NewRequest(http.MethodPost, "/api/v1/rate/bans/release", bytes.NewReader(releaseBody))
	relReq.AddCookie(sessionCookie)
	relRec := httptest.NewRecorder()
	server.ServeHTTP(relRec, relReq)
	require.Equal(t, http.StatusOK, relRec.Code)
	require.Equal(t, "198.51.100.101", pub.unblockCalled)

	// Verify ban was evicted
	require.Len(t, bm.ListBans(), 1)

	// 4. Release all bans ("UNBLOCK ALL")
	relAllReq := httptest.NewRequest(http.MethodPost, "/api/v1/rate/bans/release-all", nil)
	relAllReq.AddCookie(sessionCookie)
	relAllRec := httptest.NewRecorder()
	server.ServeHTTP(relAllRec, relAllReq)
	require.Equal(t, http.StatusOK, relAllRec.Code)
	require.True(t, pub.unblockAllCalled)
	require.Len(t, bm.ListBans(), 0)

	// 5. Waiting Room Metrics API
	metricsReq := httptest.NewRequest(http.MethodGet, "/api/v1/waiting-room/metrics", nil)
	metricsReq.AddCookie(sessionCookie)
	metricsRec := httptest.NewRecorder()
	server.ServeHTTP(metricsRec, metricsReq)
	require.Equal(t, http.StatusOK, metricsRec.Code)
	var metrics rate.WaitingRoomMetrics
	require.NoError(t, json.Unmarshal(metricsRec.Body.Bytes(), &metrics))
	require.Equal(t, int64(0), metrics.ActiveInFlight)
	require.Equal(t, int64(0), metrics.TotalWaiting)
}
