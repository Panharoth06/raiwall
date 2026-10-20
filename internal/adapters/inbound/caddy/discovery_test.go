package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestNormalizePathTemplate(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/api/v1/users/123", "/api/v1/users/{id}"},
		{"/api/v1/users/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "/api/v1/users/{id}"},
		{"/api/v1/orders/123/items/456", "/api/v1/orders/{id}/items/{id}"},
		{"/api/v1/tokens/abcdef0123456789abcdef0123456789", "/api/v1/tokens/{hash}"},
		{"/static/css/style.css", "/static/css/style.css"},
		{"/api/v1/search?q=test&limit=10", "/api/v1/search"},
		{"/api/v1/users/123/", "/api/v1/users/{id}/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			actual := NormalizePathTemplate(tt.input)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestAPIDiscoveryCataloger_AggregateAndFlush(t *testing.T) {
	store, err := sqlite.InitDB("file:discovery_test.db?mode=memory&cache=shared")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_ = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:        "app-test-disc",
		Name:      "Discovery App",
		Hostnames: "[\"api.example.com\"]",
		Mode:      "defense",
	})

	cataloger := NewAPIDiscoveryCataloger(store, nil, 100*time.Millisecond)
	defer cataloger.Close()

	// Record clean requests
	cataloger.RecordRequest("app-test-disc", "GET", "/api/v1/users/42", "application/json; charset=utf-8")
	cataloger.RecordRequest("app-test-disc", "GET", "/api/v1/users/99", "application/json")
	cataloger.RecordRequest("app-test-disc", "POST", "/api/v1/users", "application/json")

	// Flush to store
	cataloger.Flush(ctx)

	resources, err := store.ListAPIResourcesByApp(ctx, "app-test-disc")
	require.NoError(t, err)
	require.Len(t, resources, 2)

	endpointMap := make(map[string]sqlite.RaiwallApiResource)
	for _, res := range resources {
		key := res.Method + " " + res.PathPattern
		endpointMap[key] = res
	}

	getUsers, ok := endpointMap["GET /api/v1/users/{id}"]
	require.True(t, ok)
	require.Equal(t, int64(2), getUsers.HitCount)
	require.Equal(t, "application/json", getUsers.ContentType)

	postUsers, ok := endpointMap["POST /api/v1/users"]
	require.True(t, ok)
	require.Equal(t, int64(1), postUsers.HitCount)
}

func TestMiddleware_DiscoveryIntegration(t *testing.T) {
	store, err := sqlite.InitDB("file:discovery_mw_test.db?mode=memory&cache=shared")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_ = store.CreateApp(ctx, sqlite.CreateAppParams{
		ID:        "app-live-disc",
		Name:      "Live Disc",
		Hostnames: "[\"live.example.com\"]",
		Mode:      "defense",
	})

	cataloger := NewAPIDiscoveryCataloger(store, nil, 100*time.Millisecond)
	defer cataloger.Close()

	app := &control.AppConfig{
		ID:        "app-live-disc",
		Name:      "Live Disc",
		Hostnames: []string{"live.example.com"},
		Mode:      control.ModeDefense,
	}
	snap := control.NewConfigSnapshot(12, control.ModeDefense, []*control.AppConfig{app})
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	mw := &Middleware{
		Mode:               "defense",
		engine:             waf.NewSemanticEngine(),
		discoveryCataloger: cataloger,
	}

	// 1. Send clean transit request
	req := httptest.NewRequest(http.MethodGet, "http://live.example.com/api/v1/items/888", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = mw.ServeHTTP(rec, req, next)
	require.NoError(t, err)
	require.True(t, next.invoked)

	time.Sleep(30 * time.Millisecond)
	cataloger.Flush(ctx)

	resources, err := store.ListAPIResourcesByApp(ctx, "app-live-disc")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "GET", resources[0].Method)
	require.Equal(t, "/api/v1/items/{id}", resources[0].PathPattern)
}
