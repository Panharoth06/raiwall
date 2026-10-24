package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

func TestTelemetryAPI_Endpoints(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "api_test.db")

	store, err := sqlite.NewTelemetryStore(sqlite.TelemetryConfig{
		DSN: fmt.Sprintf("file:%s", dbPath),
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	_ = store.SaveBatch(ctx, []*telemetry.ForensicEvent{
		{
			EventID:   "evt-1",
			Timestamp: now.Add(-2 * time.Minute),
			Host:      "example.com",
			Path:      "/login",
			ClientIP:  "192.168.1.1",
			Action:    "block",
			RuleID:    "SQLI",
			Severity:  "high",
			GeoData:   telemetry.GeoData{Country: "US"},
		},
		{
			EventID:   "evt-2",
			Timestamp: now.Add(-1 * time.Minute),
			Host:      "example.com",
			Path:      "/search",
			ClientIP:  "192.168.1.2",
			Action:    "allow",
			Severity:  "info",
			GeoData:   telemetry.GeoData{Country: "DE"},
		},
	})

	streamer := NewEventStreamer()
	metrics := telemetry.NewMetrics(nil)
	metrics.RecordRequest("GET", "200", "allow", 5*time.Millisecond)
	api := NewTelemetryAPI(store, streamer, metrics)

	// 1. Test GET /.raiwall/api/events
	reqEvents := httptest.NewRequest(http.MethodGet, "/.raiwall/api/events?action=block", nil)
	recEvents := httptest.NewRecorder()
	api.ServeHTTP(recEvents, reqEvents)

	if recEvents.Code != http.StatusOK {
		t.Fatalf("expected 200 from /events, got %d", recEvents.Code)
	}

	var resEvents telemetry.QueryResult
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

	var resStats telemetry.AggregateStats
	if err := json.Unmarshal(recStats.Body.Bytes(), &resStats); err != nil {
		t.Fatalf("unmarshal stats response: %v", err)
	}
	if resStats.TotalRequests != 2 || resStats.TotalBlocked != 1 {
		t.Errorf("unexpected stats: %+v", resStats)
	}
	if resStats.UniqueIPs < 1 {
		t.Errorf("expected at least 1 unique IP in stats, got %d", resStats.UniqueIPs)
	}

	// 2b. Test GET /.raiwall/api/events/stats with host and country filter
	reqStatsFiltered := httptest.NewRequest(http.MethodGet, "/.raiwall/api/events/stats?host=api.corp.local&country=US", nil)
	recStatsFiltered := httptest.NewRecorder()
	api.ServeHTTP(recStatsFiltered, reqStatsFiltered)
	if recStatsFiltered.Code != http.StatusOK {
		t.Fatalf("expected 200 from filtered /events/stats, got %d", recStatsFiltered.Code)
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

func TestTelemetryAPI_IncidentsAndCurl(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "incidents.db")
	store, err := sqlite.NewTelemetryStore(sqlite.TelemetryConfig{DSN: fmt.Sprintf("file:%s", dbPath)})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	base := time.Now().UTC().Truncate(5 * time.Minute).Add(-30 * time.Minute)
	events := []*telemetry.ForensicEvent{
		{
			EventID: "inc-a1", Timestamp: base, Host: "shop.example.com", Path: "/search?q=x",
			Method: "GET", ClientIP: "203.0.113.7", Action: "block", RuleID: "SEMANTIC_SQLI",
			Severity: "high", PayloadLocation: "QUERY", MatchedToken: "' OR 1=1--",
			AttackCategory: "SQL Injection",
		},
		{
			EventID: "inc-a2", Timestamp: base.Add(90 * time.Second), Host: "shop.example.com", Path: "/login",
			Method: "POST", ClientIP: "203.0.113.7", Action: "block", RuleID: "SEMANTIC_SQLI",
			Severity: "critical", PayloadLocation: "BODY", MatchedToken: "UNION SELECT",
			AttackCategory: "SQL Injection",
		},
		{
			EventID: "inc-a3", Timestamp: base.Add(10 * time.Minute), Host: "shop.example.com", Path: "/cart",
			Method: "GET", ClientIP: "203.0.113.7", Action: "allow", RuleID: "SEMANTIC_XSS",
			Severity: "low", AttackCategory: "XSS",
		},
		{
			EventID: "inc-b1", Timestamp: base.Add(30 * time.Second), Host: "shop.example.com", Path: "/admin",
			Method: "GET", ClientIP: "198.51.100.9", Action: "ban", RuleID: "RATE_TIER2",
			Severity: "high",
		},
		{
			EventID: "inc-c1", Timestamp: base.Add(45 * time.Second), Host: "api.example.com", Path: "/v1/pay",
			Method: "POST", ClientIP: "203.0.113.7", Action: "block", RuleID: "SEMANTIC_CMD",
			Severity: "medium",
		},
	}
	if err := store.SaveBatch(context.Background(), events); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	api := NewTelemetryAPI(store, nil, nil)
	window := fmt.Sprintf("start_time=%s&end_time=%s",
		url.QueryEscape(base.Add(-time.Hour).Format(time.RFC3339)),
		url.QueryEscape(base.Add(time.Hour).Format(time.RFC3339)))

	// Incidents group by client_ip + host + 5-minute window.
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/incidents?"+window, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from incidents, got %d: %s", rec.Code, rec.Body.String())
	}
	var res telemetry.IncidentQueryResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal incidents: %v", err)
	}
	if res.TotalCount != 4 || len(res.Incidents) != 4 {
		t.Fatalf("expected 4 incidents, got total=%d len=%d", res.TotalCount, len(res.Incidents))
	}

	var sqlIncident *telemetry.Incident
	for _, inc := range res.Incidents {
		if inc.ClientIP == "203.0.113.7" && inc.TotalEvents == 2 {
			sqlIncident = inc
		}
	}
	if sqlIncident == nil {
		t.Fatalf("expected a 2-event SQLi incident, got %+v", res.Incidents)
	}
	if sqlIncident.TotalBlocked != 2 || sqlIncident.MaxSeverity != "critical" {
		t.Errorf("unexpected incident stats: %+v", sqlIncident)
	}
	if sqlIncident.Category != "SQL Injection" {
		t.Errorf("expected SQL Injection category, got %q", sqlIncident.Category)
	}
	if sqlIncident.StartTime.IsZero() || sqlIncident.EndTime.IsZero() {
		t.Errorf("expected incident window timestamps, got %+v", sqlIncident)
	}

	// Host/ip filters narrow the aggregation.
	recFiltered := httptest.NewRecorder()
	api.ServeHTTP(recFiltered, httptest.NewRequest(http.MethodGet,
		"/api/v1/telemetry/incidents?host=api.example.com&"+window, nil))
	var filtered telemetry.IncidentQueryResult
	if err := json.Unmarshal(recFiltered.Body.Bytes(), &filtered); err != nil {
		t.Fatalf("unmarshal filtered incidents: %v", err)
	}
	if filtered.TotalCount != 1 || len(filtered.Incidents) != 1 || filtered.Incidents[0].Host != "api.example.com" {
		t.Errorf("expected single api.example.com incident, got %+v", filtered)
	}

	// Reproducible cURL command for a stored event.
	recCurl := httptest.NewRecorder()
	api.ServeHTTP(recCurl, httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/events/inc-a2/curl", nil))
	if recCurl.Code != http.StatusOK {
		t.Fatalf("expected 200 from curl, got %d: %s", recCurl.Code, recCurl.Body.String())
	}
	var curlRes struct {
		Curl string `json:"curl"`
	}
	if err := json.Unmarshal(recCurl.Body.Bytes(), &curlRes); err != nil {
		t.Fatalf("unmarshal curl response: %v", err)
	}
	if !strings.HasPrefix(curlRes.Curl, "curl -X POST 'http://shop.example.com/login'") {
		t.Errorf("unexpected curl command: %q", curlRes.Curl)
	}

	recMissing := httptest.NewRecorder()
	api.ServeHTTP(recMissing, httptest.NewRequest(http.MethodGet, "/api/v1/telemetry/events/nope/curl", nil))
	if recMissing.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown event, got %d", recMissing.Code)
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

	time.Sleep(50 * time.Millisecond)

	if streamer.SubscriberCount() != 1 {
		t.Fatalf("expected 1 subscriber, got %d", streamer.SubscriberCount())
	}

	// 1. Broadcast non-matching event (Country = "DE")
	streamer.Broadcast(&telemetry.ForensicEvent{
		EventID: "evt-de",
		GeoData: telemetry.GeoData{Country: "DE"},
	})

	// 2. Broadcast matching event (Country = "US")
	streamer.Broadcast(&telemetry.ForensicEvent{
		EventID: "evt-us",
		Action:  "block",
		GeoData: telemetry.GeoData{Country: "US"},
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
