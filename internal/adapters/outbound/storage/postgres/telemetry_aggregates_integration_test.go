//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
)

// TestTelemetryStore_AggregateParityPostgres requires a live PostgreSQL
// instance. Set RAIWALL_TEST_POSTGRES_DSN to run it, for example:
//
//	RAIWALL_TEST_POSTGRES_DSN='postgres://postgres:postgres@127.0.0.1:5432/raiwall?sslmode=disable' \
//	  go test -tags=integration ./internal/adapters/outbound/storage/postgres -run AggregateParity -v
func TestTelemetryStore_AggregateParityPostgres(t *testing.T) {
	dsn := os.Getenv("RAIWALL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set RAIWALL_TEST_POSTGRES_DSN to run PostgreSQL aggregate parity test")
	}

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Ping())

	store := NewTelemetryStore(db, 0, 0)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	eventPrefix := "agg-" + suffix + "-"
	hostA := "agg-a-" + suffix + ".example.test"
	hostB := "agg-b-" + suffix + ".example.test"
	countryA := "XA"
	countryB := "XB"
	base := time.Now().UTC().Truncate(time.Second)

	seed := []*telemetry.ForensicEvent{
		{
			EventID: eventPrefix + "1", Timestamp: base.Add(-2 * time.Second), Host: hostA,
			Path: "/landing", Method: "GET", ClientIP: "10.10.0.1", Action: "allow",
			StatusCode: 200, GeoData: telemetry.GeoData{Country: countryA},
		},
		{
			EventID: eventPrefix + "2", Timestamp: base.Add(-3 * time.Minute), Host: hostA,
			Path: "/login", Method: "POST", ClientIP: "10.10.0.2", Action: "block",
			RuleID: "SEMANTIC_SQLI", StatusCode: 403, AttackCategory: "sql_inj",
			GeoData: telemetry.GeoData{Country: countryB},
		},
		{
			EventID: eventPrefix + "3", Timestamp: base.Add(-4 * time.Minute), Host: hostB,
			Path: "/api/items", Method: "POST", ClientIP: "10.10.0.1", Action: "allow",
			StatusCode: 200, GeoData: telemetry.GeoData{Country: countryA},
		},
		{
			EventID: eventPrefix + "4", Timestamp: base.Add(-5 * time.Minute), Host: hostB,
			Path: "/broken", Method: "GET", ClientIP: "10.10.0.3", Action: "allow",
			StatusCode: 500, GeoData: telemetry.GeoData{Country: countryB},
		},
	}
	require.NoError(t, store.SaveBatch(ctx, seed))
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM forensic_events WHERE event_id LIKE $1", eventPrefix+"%")
	})

	hostStats, err := store.QueryAggregates(ctx, base.Add(-time.Hour), base.Add(time.Minute),
		telemetry.AggregateFilter{Host: hostA})
	require.NoError(t, err)
	require.EqualValues(t, 2, hostStats.TotalRequests)
	require.EqualValues(t, 1, hostStats.TotalBlocked)
	require.EqualValues(t, 1, hostStats.PageViews)
	require.EqualValues(t, 2, hostStats.UniqueIPs)
	require.EqualValues(t, 2, hostStats.UniqueVisitors)
	require.EqualValues(t, 1, hostStats.BlockedIPs)
	require.EqualValues(t, 1, hostStats.Status4xx)
	require.EqualValues(t, 1, hostStats.Status4xxBlocked)
	require.EqualValues(t, 0, hostStats.Status5xx)
	require.InDelta(t, 0.5, hostStats.BlockRatio, 1e-9)
	require.Len(t, hostStats.TopCategories, 1)
	require.Equal(t, "sql_inj", hostStats.TopCategories[0].Key)

	countryStats, err := store.QueryAggregates(ctx, base.Add(-time.Hour), base.Add(time.Minute),
		telemetry.AggregateFilter{Country: countryA})
	require.NoError(t, err)
	require.EqualValues(t, 2, countryStats.TotalRequests)
	require.EqualValues(t, 0, countryStats.TotalBlocked)
	require.EqualValues(t, 1, countryStats.PageViews)
	require.EqualValues(t, 1, countryStats.UniqueIPs)
	require.EqualValues(t, 0, countryStats.BlockedIPs)
	require.EqualValues(t, 0, countryStats.Status4xx)
	require.EqualValues(t, 0, countryStats.Status5xx)
	require.Len(t, countryStats.TopIPs, 1)
	require.Equal(t, "10.10.0.1", countryStats.TopIPs[0].Key)
	require.EqualValues(t, 2, countryStats.TopIPs[0].Count)
}
