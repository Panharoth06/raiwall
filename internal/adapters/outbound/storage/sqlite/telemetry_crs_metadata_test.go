package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// TestTelemetryStore_CRSMetadataRoundTrip verifies engine, anomaly score,
// paranoia level and matched rules survive storage and querying.
func TestTelemetryStore_CRSMetadataRoundTrip(t *testing.T) {
	store, err := NewTelemetryStore(TelemetryConfig{
		DSN: fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", filepath.Join(t.TempDir(), "crs_meta.db")),
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	want := &telemetry.ForensicEvent{
		EventID:       "evt-crs-meta",
		Timestamp:     time.Now().UTC().Truncate(time.Second),
		Host:          "example.com",
		Path:          "/login",
		Method:        "POST",
		ClientIP:      "203.0.113.10",
		Action:        "audit",
		Severity:      "low",
		RuleID:        "CRS_949110",
		Engine:        "crs",
		AnomalyScore:  7,
		ParanoiaLevel: 1,
		MatchedRules: []string{
			"942100: SQL Injection Attack Detected via libinjection [CRITICAL]",
			"949110: Inbound Anomaly Score Exceeded [CRITICAL]",
		},
	}

	if err := store.SaveBatch(context.Background(), []*telemetry.ForensicEvent{want}); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.GetEventByID(context.Background(), want.EventID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("event not found")
	}
	if got.Engine != want.Engine || got.AnomalyScore != want.AnomalyScore || got.ParanoiaLevel != want.ParanoiaLevel {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if len(got.MatchedRules) != len(want.MatchedRules) || got.MatchedRules[0] != want.MatchedRules[0] {
		t.Fatalf("matched rules mismatch: %v", got.MatchedRules)
	}

	res, err := store.Query(context.Background(), telemetry.QueryParams{Limit: 5})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 1 || res.Events[0].Engine != "crs" || res.Events[0].AnomalyScore != 7 {
		t.Fatalf("query metadata mismatch: %+v", res.Events)
	}
}
