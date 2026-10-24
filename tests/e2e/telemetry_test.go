//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	api "github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/alerts"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

func TestEndToEndTelemetry(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	// 1. Setup in-memory mock alert sender (avoids sandbox socket restriction)
	var alertMu sync.Mutex
	var receivedAlerts []string
	alertSender := &testAlertSender{
		onSend: func(ctx context.Context, rawURL, message string) error {
			alertMu.Lock()
			receivedAlerts = append(receivedAlerts, message)
			alertMu.Unlock()
			return nil
		},
	}

	// 2. Setup SQLite database for telemetry
	dbPath := filepath.Join(t.TempDir(), "test-e2e-telemetry.db")

	// 3. Setup mock protected upstream backend
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/api/v1/products", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":["item1","item2"]}`))
	})
	next := &e2eNextHandler{handler: backendMux}

	// 4. Configure Raiwall Middleware with full telemetry pipeline
	mw := &caddy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
		TelemetryConfig: &caddy.TelemetrySettings{
			StorageType:   "sqlite",
			StoragePath:   dbPath,
			FlushInterval: caddyv2.Duration(50 * time.Millisecond),
			BufferSize:    1000,
			Retention:     caddyv2.Duration(24 * time.Hour),
			AlertChannels: []caddy.AlertChannelSettings{
				{
					Name:     "e2e_alert_webhook",
					URL:      "https://hooks.slack.com/services/test",
					Events:   []string{"block", "critical"},
					Cooldown: caddyv2.Duration(5 * time.Second),
				},
			},
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}
	defer func() { _ = mw.Cleanup() }()

	// Inject the mock alert sender to capture alerts in-memory without loopback socket dials
	mw.SetAlertEngine(alerts.NewAlertEngine([]alerts.AlertChannel{
		{
			Name:     "e2e_alert_webhook",
			URL:      "https://hooks.slack.com/services/test",
			Events:   []string{"block", "critical"},
			Cooldown: 5 * time.Second,
		},
	}, 5*time.Second, alertSender))

	// 5. Test SSE live subscriber connection
	streamer := mw.EventStreamer()
	if streamer == nil {
		t.Fatal("expected EventStreamer to be initialized")
	}
	sub, unsubscribe := streamer.Subscribe(api.EventFilter{})
	defer unsubscribe()

	// 6. Send benign request -> verify allowed and proxied to backend
	{
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/products", nil)
		req.RemoteAddr = "192.0.2.10:54321"
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("benign request error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "item1") {
			t.Errorf("expected backend response, got %s", rec.Body.String())
		}
	}

	// 7. Send attack request (SQL Injection with sensitive Authorization header and Card PAN)
	var blockedEventID string
	{
		attackBody := `{"query":"select","card":"4532 0150 1234 5678"}`
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=1'%20OR%20'1'='1", strings.NewReader(attackBody))
		req.RemoteAddr = "198.51.100.25:12345"
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken")
		req.Header.Set("Cookie", "session=supersecretcookie; logged_in=true")
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("attack request error: %v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
		}
		blockedEventID = rec.Header().Get("X-Raiwall-Event-ID")
		if blockedEventID == "" {
			t.Error("expected X-Raiwall-Event-ID header on blocked response")
		}
	}

	// 8. Verify SSE stream received the sanitized event in real time
	select {
	case ev := <-sub.Channel():
		if ev.Action != "allow" && ev.Action != "block" {
			t.Errorf("unexpected event action: %s", ev.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first SSE event")
	}

	select {
	case ev := <-sub.Channel():
		if ev.Action != "block" {
			t.Errorf("expected blocked event, got action %s", ev.Action)
		}
		if ev.Headers["Authorization"] != telemetry.RedactedValue {
			t.Errorf("expected redacted Authorization header in SSE, got %s", ev.Headers["Authorization"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for blocked SSE event")
	}

	// 9. Wait for ring buffer batch flush to SQLite (flush interval is 50ms)
	time.Sleep(200 * time.Millisecond)

	// 10. Verify SQLite persistence via Store Query
	store := mw.TelemetryStore()
	if store == nil {
		t.Fatal("expected TelemetryStore to be initialized")
	}

	queryRes, err := store.Query(context.Background(), telemetry.QueryParams{
		Action: "block",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("store.Query failed: %v", err)
	}
	if queryRes.Total == 0 || len(queryRes.Events) == 0 {
		t.Fatalf("expected stored blocked events in SQLite, got %d", queryRes.Total)
	}

	persistedEvent := queryRes.Events[0]
	if persistedEvent.Action != "block" {
		t.Errorf("expected action block, got %s", persistedEvent.Action)
	}
	if persistedEvent.RuleID != "SEMANTIC_SQLI" {
		t.Errorf("expected rule SEMANTIC_SQLI, got %s", persistedEvent.RuleID)
	}
	if persistedEvent.Headers["Authorization"] != telemetry.RedactedValue {
		t.Errorf("expected redacted Authorization in SQLite, got %s", persistedEvent.Headers["Authorization"])
	}
	if persistedEvent.Headers["Cookie"] != telemetry.RedactedValue {
		t.Errorf("expected redacted Cookie in SQLite, got %s", persistedEvent.Headers["Cookie"])
	}
	if strings.Contains(persistedEvent.TruncatedPayload, "4532 0150 1234 5678") {
		t.Errorf("expected credit card PAN to be scrubbed from payload in SQLite, got: %s", persistedEvent.TruncatedPayload)
	}

	// 11. Verify Alert was dispatched to mock alert receiver
	alertMu.Lock()
	alertCount := len(receivedAlerts)
	alertMu.Unlock()

	// Wait up to 1 second for alert goroutine
	if alertCount == 0 {
		time.Sleep(500 * time.Millisecond)
		alertMu.Lock()
		alertCount = len(receivedAlerts)
		alertMu.Unlock()
	}
	if alertCount == 0 {
		t.Error("expected at least 1 alert notification sent to alertServer")
	} else {
		alertMu.Lock()
		alertMsg := receivedAlerts[0]
		alertMu.Unlock()
		if !strings.Contains(alertMsg, "RAIWALL WAF ALERT") {
			t.Errorf("unexpected alert format: %s", alertMsg)
		}
	}

	// Verify debouncer suppresses duplicate alert within cooldown window
	{
		attackBody := `{"query":"select","card":"4532 0150 1234 5678"}`
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=1'%20OR%20'1'='1", strings.NewReader(attackBody))
		req.RemoteAddr = "198.51.100.25:12345"
		rec := httptest.NewRecorder()
		_ = mw.ServeHTTP(rec, req, next)
		time.Sleep(100 * time.Millisecond)

		alertMu.Lock()
		countAfterDup := len(receivedAlerts)
		alertMu.Unlock()
		if countAfterDup != alertCount {
			t.Errorf("expected debouncer to suppress duplicate alert during cooldown, got %d alerts (initial: %d)", countAfterDup, alertCount)
		}
	}

	// 12. Test internal Prometheus Metrics endpoint (/.raiwall/metrics)
	{
		req := httptest.NewRequest(http.MethodGet, "http://example.com/.raiwall/metrics", nil)
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("metrics endpoint error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for /metrics, got %d", rec.Code)
		}
		metricsOutput := rec.Body.String()
		if !strings.Contains(metricsOutput, "raiwall_requests_total") {
			t.Errorf("expected raiwall_requests_total in metrics output")
		}
		if !strings.Contains(metricsOutput, "raiwall_blocked_total") {
			t.Errorf("expected raiwall_blocked_total in metrics output")
		}
	}

	// 13. Test internal REST API Stats endpoint (/.raiwall/api/events/stats)
	{
		req := httptest.NewRequest(http.MethodGet, "http://example.com/.raiwall/api/events/stats", nil)
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("api stats error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for stats, got %d", rec.Code)
		}
		var stats telemetry.AggregateStats
		if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
			t.Fatalf("failed to decode stats JSON: %v", err)
		}
		if stats.TotalBlocked == 0 {
			t.Errorf("expected total_blocked > 0 in stats, got %d", stats.TotalBlocked)
		}
	}

	// 14. Test Embedded UI Admin Dashboard (/.raiwall/ and SPA fallback /.raiwall/inspector)
	{
		req := httptest.NewRequest(http.MethodGet, "http://example.com/.raiwall", nil)
		rec := httptest.NewRecorder()

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ui endpoint error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for /.raiwall, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Raiwall WAF") {
			t.Errorf("expected Raiwall WAF in UI HTML, got: %s", rec.Body.String()[:min(200, rec.Body.Len())])
		}

		// Test SPA fallback
		reqSPA := httptest.NewRequest(http.MethodGet, "http://example.com/.raiwall/inspector", nil)
		recSPA := httptest.NewRecorder()
		errSPA := mw.ServeHTTP(recSPA, reqSPA, next)
		if errSPA != nil {
			t.Fatalf("ui spa fallback error: %v", errSPA)
		}
		if recSPA.Code != http.StatusOK {
			t.Errorf("expected 200 OK for SPA fallback, got %d", recSPA.Code)
		}
		if !strings.Contains(recSPA.Body.String(), "Raiwall WAF") {
			t.Errorf("expected Raiwall WAF in SPA HTML")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type testAlertSender struct {
	onSend func(ctx context.Context, rawURL, message string) error
}

func (s *testAlertSender) Send(ctx context.Context, rawURL, message string) error {
	if s.onSend != nil {
		return s.onSend(ctx, rawURL, message)
	}
	return nil
}
