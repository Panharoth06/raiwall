package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/stretchr/testify/require"
)

type fakeClusterStatusProvider struct {
	status ClusterStatus
}

func (f fakeClusterStatusProvider) ClusterStatus(context.Context) ClusterStatus { return f.status }

func loginTestAdmin(t *testing.T, server *Server, store control.ControlStore) *http.Cookie {
	t.Helper()

	hash, err := HashPassword("AdminPass123!")
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, store.CreateUser(context.Background(), control.UserRecord{
		ID:           "u-" + t.Name(),
		Username:     "admin-" + t.Name(),
		PasswordHash: hash,
		Role:         RoleAdmin,
		IsActive:     1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}))

	body, err := json.Marshal(map[string]string{
		"username": "admin-" + t.Name(),
		"password": "AdminPass123!",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)
	return cookies[0]
}

func getClusterStatus(t *testing.T, server *Server, cookie *http.Cookie) ClusterStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var status ClusterStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	return status
}

func TestClusterStatusStandaloneReportsRealState(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	previous := control.GetActiveSnapshot()
	t.Cleanup(func() { control.StoreSnapshot(previous) })
	control.StoreSnapshot(control.NewConfigSnapshot(7, control.ModeDefense, nil))

	bm := rate.NewBanManager(nil)
	defer bm.Close()
	bm.ApplyRemoteBan(&rate.BanEntry{
		Key:       "203.0.113.77",
		ClientIP:  "203.0.113.77",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	server.SetBanManager(bm)

	status := getClusterStatus(t, server, cookie)
	require.Equal(t, "standalone", status.Mode)
	require.False(t, status.RedisConnected)
	require.Equal(t, uint64(7), status.ActiveVersion)
	require.Equal(t, uint64(7), status.AppliedVersion)
	require.Equal(t, defaultClusterChannel, status.Channel)
	require.Equal(t, 1, status.BanCount)
}

func TestClusterStatusUsesProviderWhenWired(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	server.SetClusterStatusProvider(fakeClusterStatusProvider{status: ClusterStatus{
		Mode:           "redis",
		RedisConnected: true,
		Channel:        "raiwall:test:events",
		ActiveVersion:  9,
		AppliedVersion: 8,
		AppliedHash:    "abc123",
		LastApplyError: "hash mismatch",
		BanCount:       4,
	}})

	status := getClusterStatus(t, server, cookie)
	require.Equal(t, "redis", status.Mode)
	require.True(t, status.RedisConnected)
	require.Equal(t, "raiwall:test:events", status.Channel)
	require.Equal(t, uint64(9), status.ActiveVersion)
	require.Equal(t, uint64(8), status.AppliedVersion)
	require.Equal(t, "abc123", status.AppliedHash)
	require.Equal(t, "hash mismatch", status.LastApplyError)
	require.Equal(t, 4, status.BanCount)
}
