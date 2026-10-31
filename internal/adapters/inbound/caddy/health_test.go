package caddy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestHealthAndReadinessProbes(t *testing.T) {
	store, err := sqlite.InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	previous := control.GetActiveSnapshot()
	control.StoreSnapshot(control.NewConfigSnapshot(1, control.ModeDefense, nil))
	t.Cleanup(func() { control.StoreSnapshot(previous) })
	mw := &Middleware{controlStore: store}

	health := httptest.NewRecorder()
	require.True(t, mw.serveHealth(health, httptest.NewRequest(http.MethodGet, "/.raiwall/healthz", nil)))
	require.Equal(t, http.StatusOK, health.Code)

	ready := httptest.NewRecorder()
	require.True(t, mw.serveHealth(ready, httptest.NewRequest(http.MethodGet, "/.raiwall/readyz", nil)))
	require.Equal(t, http.StatusOK, ready.Code)
	require.Contains(t, ready.Body.String(), `"status":"ready"`)
	require.NotContains(t, ready.Body.String(), "database", "readiness must not enumerate components")

	require.NoError(t, store.Close())
	broken := httptest.NewRecorder()
	require.True(t, mw.serveHealth(broken, httptest.NewRequest(http.MethodGet, "/.raiwall/readyz", nil)))
	require.Equal(t, http.StatusServiceUnavailable, broken.Code)
	require.Contains(t, broken.Body.String(), `"status":"not_ready"`)
	require.NotContains(t, broken.Body.String(), "database")

	other := httptest.NewRecorder()
	require.False(t, mw.serveHealth(other, httptest.NewRequest(http.MethodGet, "/healthz", nil)))
}

func TestHealthRejectsNonGet(t *testing.T) {
	mw := &Middleware{}
	rec := httptest.NewRecorder()
	require.True(t, mw.serveHealth(rec, httptest.NewRequest(http.MethodPost, "/.raiwall/healthz", nil)))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
