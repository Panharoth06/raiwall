package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

func TestTelemetryStore_BatchQueryAndAggregates(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_forensics.db")

	store, err := NewTelemetryStore(TelemetryConfig{
		DSN:       fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", dbPath),
		Retention: 0,
	})
	if err != nil {
		t.Fatalf("failed to create telemetry store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	events := make([]*telemetry.ForensicEvent, 0, 15)
	for i := 1; i <= 15; i++ {
		action := "allow"
		ruleID := ""
		severity := "info"
		country := "US"
		clientIP := fmt.Sprintf("192.168.1.%d", i)

		if i%3 == 0 {
			action = "block"
			ruleID = "SEMANTIC_SQLI"
			severity = "high"
			country = "CN"
		} else if i%5 == 0 {
			action = "ban"
			ruleID = "RATE_LIMIT_TIER2"
			severity = "critical"
			country = "RU"
		}

		events = append(events, &telemetry.ForensicEvent{
			EventID:   fmt.Sprintf("evt-%03d", i),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Host:      "example.com",
			Path:      fmt.Sprintf("/resource/%d", i),
			Method:    "POST",
			ClientIP:  clientIP,
			JA4:       "t13d1516h2_8daaf6152771_b186095e22b6",
			GeoData: telemetry.GeoData{
				Country:   country,
				Continent: "NA",
				ASN:       uint(1000 + i),
				Latitude:  10.0,
				Longitude: 20.0,
			},
			RuleID:           ruleID,
			Action:           action,
			Severity:         severity,
			Headers:          map[string]string{"User-Agent": "test-agent"},
			TruncatedPayload: fmt.Sprintf("payload-%d", i),
			Latency:          2500 * time.Microsecond,
			StatusCode:       200,
		})
	}

	if err := store.SaveBatch(ctx, events); err != nil {
		t.Fatalf("failed to save batch: %v", err)
	}

	resAll, err := store.Query(ctx, telemetry.QueryParams{Limit: 20})
	if err != nil {
		t.Fatalf("query all failed: %v", err)
	}
	if resAll.Total != 15 {
		t.Errorf("expected 15 total events, got %d", resAll.Total)
	}
	if len(resAll.Events) != 15 {
		t.Errorf("expected 15 fetched events, got %d", len(resAll.Events))
	}

	resBlock, err := store.Query(ctx, telemetry.QueryParams{Action: "block"})
	if err != nil {
		t.Fatalf("query block failed: %v", err)
	}
	if resBlock.Total != 5 {
		t.Errorf("expected 5 blocked events, got %d", resBlock.Total)
	}

	resCN, err := store.Query(ctx, telemetry.QueryParams{Country: "CN"})
	if err != nil {
		t.Fatalf("query CN failed: %v", err)
	}
	if resCN.Total != 5 {
		t.Errorf("expected 5 CN events, got %d", resCN.Total)
	}

	resPage, err := store.Query(ctx, telemetry.QueryParams{Limit: 5, Offset: 5})
	if err != nil {
		t.Fatalf("query page failed: %v", err)
	}
	if len(resPage.Events) != 5 {
		t.Errorf("expected 5 events in page, got %d", len(resPage.Events))
	}
	if resPage.Total != 15 {
		t.Errorf("expected total 15 for page, got %d", resPage.Total)
	}

	stats, err := store.QueryAggregates(ctx, now.Add(-time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("query aggregates failed: %v", err)
	}
	if stats.TotalRequests != 15 {
		t.Errorf("expected 15 total requests in aggregates, got %d", stats.TotalRequests)
	}
	if stats.TotalBlocked != 7 {
		t.Errorf("expected 7 blocked/banned requests, got %d", stats.TotalBlocked)
	}
	if stats.BlockRatio <= 0 {
		t.Errorf("expected positive block ratio, got %f", stats.BlockRatio)
	}
	if len(stats.TopCountries) == 0 {
		t.Errorf("expected non-empty TopCountries")
	}
	if len(stats.TopRules) == 0 {
		t.Errorf("expected non-empty TopRules")
	}
	if len(stats.TopIPs) == 0 {
		t.Errorf("expected non-empty TopIPs")
	}
	if len(stats.TimeBuckets) == 0 {
		t.Errorf("expected non-empty TimeBuckets")
	}

	pruned, err := store.Prune(ctx, -10*time.Minute)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if pruned == 0 {
		t.Errorf("expected pruned events > 0, got %d", pruned)
	}
}

func TestTelemetryStore_AggregateFieldParity(t *testing.T) {
	store, err := NewTelemetryStore(TelemetryConfig{
		DSN: fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", filepath.Join(t.TempDir(), "parity.db")),
	})
	if err != nil {
		t.Fatalf("failed to create telemetry store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	seed := []*telemetry.ForensicEvent{
		{
			EventID: "parity-1", Timestamp: now.Add(-2 * time.Second), Host: "a.example.test",
			Path: "/landing", Method: "GET", ClientIP: "192.0.2.10", Action: "allow",
			StatusCode: 200, GeoData: telemetry.GeoData{Country: "US"},
		},
		{
			EventID: "parity-2", Timestamp: now.Add(-3 * time.Minute), Host: "a.example.test",
			Path: "/login", Method: "POST", ClientIP: "192.0.2.20", Action: "block",
			RuleID: "SEMANTIC_SQLI", StatusCode: 403, AttackCategory: "sql_inj",
			GeoData: telemetry.GeoData{Country: "CN"},
		},
		{
			EventID: "parity-3", Timestamp: now.Add(-4 * time.Minute), Host: "b.example.test",
			Path: "/api/items", Method: "POST", ClientIP: "192.0.2.10", Action: "allow",
			StatusCode: 200, GeoData: telemetry.GeoData{Country: "US"},
		},
		{
			EventID: "parity-4", Timestamp: now.Add(-5 * time.Minute), Host: "b.example.test",
			Path: "/broken", Method: "GET", ClientIP: "192.0.2.30", Action: "allow",
			StatusCode: 500, GeoData: telemetry.GeoData{Country: "CN"},
		},
	}
	if err := store.SaveBatch(ctx, seed); err != nil {
		t.Fatalf("failed to save batch: %v", err)
	}

	stats, err := store.QueryAggregates(ctx, now.Add(-time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("query aggregates failed: %v", err)
	}

	assertAggregateStats(t, stats, aggregateExpectation{
		total: 4, blocked: 1, pageViews: 1, uniqueIPs: 3, blockedIPs: 1,
		status4xx: 1, status4xxBlocked: 1, status5xx: 1,
	})
	if stats.QPS <= 0 {
		t.Fatalf("expected live QPS > 0 for the event recorded seconds ago, got %f", stats.QPS)
	}
	if len(stats.TimeBuckets) == 0 {
		t.Fatal("expected non-empty time buckets")
	}

	hostStats, err := store.QueryAggregates(ctx, now.Add(-time.Hour), now.Add(time.Minute),
		telemetry.AggregateFilter{Host: "a.example.test"})
	if err != nil {
		t.Fatalf("query host-filtered aggregates failed: %v", err)
	}
	assertAggregateStats(t, hostStats, aggregateExpectation{
		total: 2, blocked: 1, pageViews: 1, uniqueIPs: 2, blockedIPs: 1,
		status4xx: 1, status4xxBlocked: 1, status5xx: 0,
	})
	if len(hostStats.TopCategories) != 1 || hostStats.TopCategories[0].Key != "sql_inj" {
		t.Fatalf("expected sql_inj category for host filter, got %+v", hostStats.TopCategories)
	}

	countryStats, err := store.QueryAggregates(ctx, now.Add(-time.Hour), now.Add(time.Minute),
		telemetry.AggregateFilter{Country: "US"})
	if err != nil {
		t.Fatalf("query country-filtered aggregates failed: %v", err)
	}
	assertAggregateStats(t, countryStats, aggregateExpectation{
		total: 2, blocked: 0, pageViews: 1, uniqueIPs: 1, blockedIPs: 0,
		status4xx: 0, status4xxBlocked: 0, status5xx: 0,
	})
	if countryStats.TopIPs[0].Key != "192.0.2.10" || countryStats.TopIPs[0].Count != 2 {
		t.Fatalf("unexpected top IPs for country filter: %+v", countryStats.TopIPs)
	}
}

type aggregateExpectation struct {
	total, blocked, pageViews, uniqueIPs, blockedIPs int64
	status4xx, status4xxBlocked, status5xx           int64
}

func assertAggregateStats(t *testing.T, stats *telemetry.AggregateStats, want aggregateExpectation) {
	t.Helper()
	if stats.TotalRequests != want.total ||
		stats.TotalBlocked != want.blocked ||
		stats.PageViews != want.pageViews ||
		stats.UniqueIPs != want.uniqueIPs ||
		stats.BlockedIPs != want.blockedIPs ||
		stats.Status4xx != want.status4xx ||
		stats.Status4xxBlocked != want.status4xxBlocked ||
		stats.Status5xx != want.status5xx {
		t.Fatalf("unexpected aggregate stats: %+v (want %+v)", stats, want)
	}
	if stats.TotalRequests > 0 {
		if got, wantRatio := stats.BlockRatio, float64(want.blocked)/float64(want.total); got != wantRatio {
			t.Fatalf("block ratio = %v, want %v", got, wantRatio)
		}
	}
	if stats.UniqueVisitors != stats.UniqueIPs {
		t.Fatalf("unique visitors = %d, want unique IPs %d", stats.UniqueVisitors, stats.UniqueIPs)
	}
}

func TestTelemetryStore_IncidentAggregationAndLocations(t *testing.T) {
	store, err := NewTelemetryStore(TelemetryConfig{
		DSN: fmt.Sprintf("file:%s", filepath.Join(t.TempDir(), "incidents.db")),
	})
	if err != nil {
		t.Fatalf("failed to create telemetry store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	base := time.Now().UTC().Truncate(5 * time.Minute).Add(-20 * time.Minute)

	seed := []*telemetry.ForensicEvent{
		{
			EventID: "loc-1", Timestamp: base, Host: "app.example.com", Path: "/q", Method: "GET",
			ClientIP: "203.0.113.10", Action: "block", RuleID: "SEMANTIC_SQLI", Severity: "high",
			PayloadLocation: "QUERY", MatchedToken: "' OR 1=1--", AttackCategory: "SQL Injection",
			ResponseHeaders: map[string][]string{"Content-Type": {"application/json"}},
			ResponseBody:    []byte(`{"error":"blocked"}`),
		},
		{
			EventID: "loc-2", Timestamp: base.Add(2 * time.Minute), Host: "app.example.com", Path: "/q2", Method: "POST",
			ClientIP: "203.0.113.10", Action: "block", RuleID: "SEMANTIC_SQLI", Severity: "critical",
			PayloadLocation: "BODY", MatchedToken: "UNION SELECT", AttackCategory: "SQL Injection",
		},
		{
			EventID: "loc-3", Timestamp: base.Add(12 * time.Minute), Host: "app.example.com", Path: "/q3", Method: "GET",
			ClientIP: "203.0.113.10", Action: "allow", RuleID: "SEMANTIC_XSS", Severity: "low",
			PayloadLocation: "URLPATH",
		},
	}
	if err := store.SaveBatch(ctx, seed); err != nil {
		t.Fatalf("save batch: %v", err)
	}

	// Parameter location fields round-trip through storage.
	got, err := store.GetEventByID(ctx, "loc-1")
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if got == nil || got.PayloadLocation != "QUERY" || got.MatchedToken != "' OR 1=1--" ||
		got.AttackCategory != "SQL Injection" {
		t.Fatalf("parameter location telemetry not persisted: %+v", got)
	}
	if string(got.ResponseBody) != `{"error":"blocked"}` {
		t.Errorf("response body not persisted: %q", got.ResponseBody)
	}
	if len(got.ResponseHeaders["Content-Type"]) != 1 {
		t.Errorf("response headers not persisted: %+v", got.ResponseHeaders)
	}

	// 5-minute sliding windows split the first two events from the third.
	res, err := store.GetAggregatedIncidents(ctx, telemetry.IncidentQueryParams{
		StartTime: base.Add(-time.Hour),
		EndTime:   base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("aggregate incidents: %v", err)
	}
	if res.TotalCount != 2 || len(res.Incidents) != 2 {
		t.Fatalf("expected 2 incident windows, got total=%d len=%d", res.TotalCount, len(res.Incidents))
	}

	var multi *telemetry.Incident
	for _, inc := range res.Incidents {
		if inc.TotalEvents == 2 {
			multi = inc
		}
	}
	if multi == nil {
		t.Fatalf("expected a 2-event incident, got %+v", res.Incidents)
	}
	if multi.TotalBlocked != 2 {
		t.Fatalf("expected 2-event blocked incident, got %+v", multi)
	}
	if multi.ID == "" || multi.StartTime.IsZero() || multi.EndTime.Before(multi.StartTime) {
		t.Errorf("incident metadata incomplete: %+v", multi)
	}
	if multi.Category != "SQL Injection" || multi.MaxSeverity != "critical" {
		t.Errorf("unexpected incident classification: %+v", multi)
	}

	filtered, err := store.GetAggregatedIncidents(ctx, telemetry.IncidentQueryParams{
		StartTime: base.Add(-time.Hour),
		EndTime:   base.Add(time.Hour),
		ClientIP:  "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("filtered incidents: %v", err)
	}
	if filtered.TotalCount != 0 || len(filtered.Incidents) != 0 {
		t.Errorf("expected no incidents for unrelated IP, got %+v", filtered)
	}
}

func TestTelemetryStore_RetentionWorker(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "retention_test.db")

	store, err := NewTelemetryStore(TelemetryConfig{
		DSN:           fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", dbPath),
		Retention:     50 * time.Millisecond,
		PruneInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	oldEvent := &telemetry.ForensicEvent{
		EventID:   "evt-old",
		Timestamp: time.Now().UTC().Add(-time.Hour),
		Host:      "localhost",
		Action:    "allow",
	}

	if err := store.SaveBatch(ctx, []*telemetry.ForensicEvent{oldEvent}); err != nil {
		t.Fatalf("failed to insert old event: %v", err)
	}

	time.Sleep(80 * time.Millisecond)

	res, err := store.Query(ctx, telemetry.QueryParams{Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if res.Total != 0 {
		t.Errorf("expected 0 events after retention pruning, got %d", res.Total)
	}
}

func TestTelemetryStore_FileCreation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "exist_test.db")

	store, err := NewTelemetryStore(TelemetryConfig{
		DSN: fmt.Sprintf("file:%s", dbPath),
	})
	if err != nil {
		t.Fatalf("open store failed: %v", err)
	}
	_ = store.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("expected sqlite database file to exist on disk at %s", dbPath)
	}
}
