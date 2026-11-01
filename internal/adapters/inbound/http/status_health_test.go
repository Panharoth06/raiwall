package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeReadiness struct {
	checks map[string]bool
}

func (f fakeReadiness) Readiness(context.Context) map[string]bool { return f.checks }

func TestStatusReportsReadinessComponents(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	server.SetReadinessProvider(fakeReadiness{checks: map[string]bool{
		"database": true,
		"snapshot": true,
		"redis":    false,
	}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Status string          `json:"status"`
		Checks map[string]bool `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "degraded", body.Status)
	require.False(t, body.Checks["redis"])
	require.True(t, body.Checks["database"])
}

type fakeReadinessWithTelemetry struct{ fakeReadiness }

func (fakeReadinessWithTelemetry) TelemetryStats() map[string]uint64 {
	return map[string]uint64{"write_failed": 7, "dropped": 1}
}

func TestStatusReportsTelemetryCounters(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)
	server.SetReadinessProvider(fakeReadinessWithTelemetry{fakeReadiness{checks: map[string]bool{"database": true}}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Telemetry map[string]uint64 `json:"telemetry"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, uint64(7), body.Telemetry["write_failed"])
}
