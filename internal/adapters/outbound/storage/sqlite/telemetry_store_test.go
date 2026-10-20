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
