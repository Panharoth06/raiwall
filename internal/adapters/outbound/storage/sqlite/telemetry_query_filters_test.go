package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// TestTelemetryStore_QueryEngineScoreSeverityFilters verifies the engine,
// minimum anomaly score and rank-based minimum severity filters.
func TestTelemetryStore_QueryEngineScoreSeverityFilters(t *testing.T) {
	store, err := NewTelemetryStore(TelemetryConfig{
		DSN: fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", filepath.Join(t.TempDir(), "filters.db")),
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	events := []*telemetry.ForensicEvent{
		{EventID: "sem-high", Timestamp: now, Action: "block", Severity: "high", Engine: "semantic"},
		{EventID: "crs-low-score", Timestamp: now, Action: "audit", Severity: "low", Engine: "crs", AnomalyScore: 3},
		{EventID: "crs-high-score", Timestamp: now, Action: "block", Severity: "critical", Engine: "crs", AnomalyScore: 15},
		{EventID: "info", Timestamp: now, Action: "allow", Severity: "info"},
	}
	if err := store.SaveBatch(context.Background(), events); err != nil {
		t.Fatalf("save batch: %v", err)
	}

	score := func(v float64) *float64 { return &v }
	cases := []struct {
		name   string
		params telemetry.QueryParams
		want   []string
	}{
		{"engine crs", telemetry.QueryParams{Engine: "crs"}, []string{"crs-high-score", "crs-low-score"}},
		{"engine semantic", telemetry.QueryParams{Engine: "semantic"}, []string{"sem-high"}},
		{"min score", telemetry.QueryParams{MinAnomalyScore: score(5)}, []string{"crs-high-score"}},
		{"min score zero keeps all", telemetry.QueryParams{MinAnomalyScore: score(0)}, []string{"crs-high-score", "crs-low-score", "info", "sem-high"}},
		{"min severity high", telemetry.QueryParams{MinSeverity: "high"}, []string{"crs-high-score", "sem-high"}},
		{"min severity low", telemetry.QueryParams{MinSeverity: "low"}, []string{"crs-high-score", "crs-low-score", "sem-high"}},
		{"combined", telemetry.QueryParams{Engine: "crs", MinSeverity: "low", MinAnomalyScore: score(1)}, []string{"crs-high-score", "crs-low-score"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := store.Query(context.Background(), tc.params)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			var got []string
			for _, e := range res.Events {
				got = append(got, e.EventID)
			}
			sort.Strings(got)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if res.Total != int64(len(tc.want)) {
				t.Fatalf("total %d, want %d", res.Total, len(tc.want))
			}
		})
	}
}
