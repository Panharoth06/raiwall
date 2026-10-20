package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetrics_RecordingAndHTTPHandler(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Record sample metrics
	m.RecordRequest("GET", "200", "allow", 15*time.Millisecond)
	m.RecordRequest("POST", "403", "block", 5*time.Millisecond)
	m.RecordBlock("sqli", "SEMANTIC_SQLI")
	m.RecordTelemetryDropped(5)
	m.SetActiveConnections(42)
	m.SetBannedIPs(7)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	expectedSubstrings := []string{
		"raiwall_requests_total{action=\"allow\",method=\"GET\",status=\"200\"} 1",
		"raiwall_requests_total{action=\"block\",method=\"POST\",status=\"403\"} 1",
		"raiwall_blocked_total{reason=\"sqli\",rule_id=\"SEMANTIC_SQLI\"} 1",
		"raiwall_telemetry_dropped_total 5",
		"raiwall_active_connections 42",
		"raiwall_banned_ips_total 7",
		"raiwall_request_duration_seconds_bucket",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(body, s) {
			t.Errorf("expected metrics output to contain %q, but got:\n%s", s, body)
		}
	}
}
