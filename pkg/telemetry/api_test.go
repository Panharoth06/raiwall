package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelemetryAPI_Endpoints(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "api_test.db")

	store, err := NewSQLiteStore(SQLiteConfig{
		DSN: fmt.Sprintf("file:%s", dbPath),
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	_ = store.SaveBatch(ctx, []*ForensicEvent{
		{
			EventID:   "evt-1",
			Timestamp: now.Add(-2 * time.Minute),
			Host:      "example.com",
			Path:      "/login",
			ClientIP:  "192.168.1.1",
			Action:    "block",
			RuleID:    "SQLI",
			Severity:  "high",
			GeoData:   GeoData{Country: "US"},
		},
		{
			EventID:   "evt-2",
			Timestamp: now.Add(-1 * time.Minute),
			Host:      "example.com",
			Path:      "/search",
			ClientIP:  "192.168.1.2",
			Action:    "allow",
			Severity:  "info",
			GeoData:   GeoData{Country: "DE"},
		},
	})

	streamer := NewEventStreamer()
	metrics := NewMetrics(nil)
	metrics.RecordRequest("GET", "200", "allow", 5*time.Millisecond)
	api := NewTelemetryAPI(store, streamer, metrics)

	// 1. Test GET /.raiwall/api/events
	reqEvents := httptest.NewRequest(http.MethodGet, "/.raiwall/api/events?action=block", nil)
	recEvents := httptest.NewRecorder()
	api.ServeHTTP(recEvents, reqEvents)

	if recEvents.Code != http.StatusOK {
		t.Fatalf("expected 200 from /events, got %d", recEvents.Code)
	}

	var resEvents QueryResult
	if err := json.Unmarshal(recEvents.Body.Bytes(), &resEvents); err != nil {
		t.Fatalf("unmarshal events response: %v", err)
	}
	if resEvents.Total != 1 || len(resEvents.Events) != 1 || resEvents.Events[0].EventID != "evt-1" {
		t.Errorf("unexpected events query result: %+v", resEvents)
	}

	// 2. Test GET /.raiwall/api/events/stats
	reqStats := httptest.NewRequest(http.MethodGet, "/.raiwall/api/events/stats", nil)
	recStats := httptest.NewRecorder()
	api.ServeHTTP(recStats, reqStats)

	if recStats.Code != http.StatusOK {
		t.Fatalf("expected 200 from /events/stats, got %d", recStats.Code)
	}

	var resStats AggregateStats
	if err := json.Unmarshal(recStats.Body.Bytes(), &resStats); err != nil {
		t.Fatalf("unmarshal stats response: %v", err)
	}
	if resStats.TotalRequests != 2 || resStats.TotalBlocked != 1 {
		t.Errorf("unexpected stats: %+v", resStats)
	}

	// 3. Test GET /.raiwall/metrics
	reqMetrics := httptest.NewRequest(http.MethodGet, "/.raiwall/metrics", nil)
	recMetrics := httptest.NewRecorder()
	api.ServeHTTP(recMetrics, reqMetrics)

	if recMetrics.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", recMetrics.Code)
	}
	if !strings.Contains(recMetrics.Body.String(), "raiwall_requests_total") {
		t.Errorf("expected metrics exposition in body, got:\n%s", recMetrics.Body.String())
	}
}

func TestTelemetryAPI_SSEStream(t *testing.T) {
	streamer := NewEventStreamer()
	api := NewTelemetryAPI(nil, streamer, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/.raiwall/api/events/stream?country=US", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		api.ServeHTTP(rec, req)
	}()

	// Wait for subscription registration
	time.Sleep(50 * time.Millisecond)

	if streamer.SubscriberCount() != 1 {
		t.Fatalf("expected 1 subscriber, got %d", streamer.SubscriberCount())
	}

	// 1. Broadcast non-matching event (Country = "DE")
	streamer.Broadcast(&ForensicEvent{
		EventID: "evt-de",
		GeoData: GeoData{Country: "DE"},
	})

	// 2. Broadcast matching event (Country = "US")
	streamer.Broadcast(&ForensicEvent{
		EventID: "evt-us",
		Action:  "block",
		GeoData: GeoData{Country: "US"},
	})

	time.Sleep(50 * time.Millisecond)
	cancel() // Disconnect client

	time.Sleep(50 * time.Millisecond)
	if streamer.SubscriberCount() != 0 {
		t.Errorf("expected 0 subscribers after cancel, got %d", streamer.SubscriberCount())
	}

	output := rec.Body.String()
	if !strings.Contains(output, "evt-us") {
		t.Errorf("expected matching event 'evt-us' in SSE stream, got:\n%s", output)
	}
	if strings.Contains(output, "evt-de") {
		t.Errorf("did not expect filtered event 'evt-de' in SSE stream, got:\n%s", output)
	}
}
