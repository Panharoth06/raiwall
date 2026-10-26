package clickhouse

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestClickHouseStore_SchemaDDL(t *testing.T) {
	store, err := NewClickHouseStore(ClickHouseConfig{
		URL:      "http://localhost:8123",
		Database: "analytics",
		Table:    "waf_events",
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ddl := store.TableSchemaDDL()
	if !strings.Contains(ddl, "analytics.waf_events") {
		t.Errorf("expected DDL to target analytics.waf_events, got: %s", ddl)
	}
	if !strings.Contains(ddl, "ENGINE = MergeTree()") {
		t.Errorf("expected MergeTree engine in DDL, got: %s", ddl)
	}
	if !strings.Contains(ddl, "PARTITION BY toYYYYMMDD(timestamp)") {
		t.Errorf("expected daily partitioning in DDL, got: %s", ddl)
	}
	if !strings.Contains(ddl, "ORDER BY (timestamp, action, rule_id, client_ip)") {
		t.Errorf("expected composite order key in DDL, got: %s", ddl)
	}
	if !strings.Contains(ddl, "CODEC(ZSTD(1))") {
		t.Errorf("expected ZSTD compression codec on payload, got: %s", ddl)
	}
}

func TestClickHouseStore_SaveBatchAndQuery(t *testing.T) {
	var batchReceived atomic.Int32
	var queryReceived atomic.Int32

	mockClient := &http.Client{
		Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
			q := r.URL.Query().Get("query")
			bodyBytes, _ := io.ReadAll(r.Body)
			bodyStr := string(bodyBytes)

			var respBody string
			statusCode := http.StatusOK

			if strings.Contains(q, "INSERT INTO") || strings.Contains(bodyStr, "INSERT INTO") {
				batchReceived.Add(1)
				respBody = "OK"
			} else if strings.Contains(q, "as page_views") || strings.Contains(bodyStr, "as page_views") {
				respBody = `{"data":[{"total":"100","blocked":"15","page_views":"70","unique_ips":"12","blocked_ips":"4","status_4xx":"20","status_4xx_blocked":"15","status_5xx":"2"}]}`
			} else if strings.Contains(q, "as recent") || strings.Contains(bodyStr, "as recent") {
				respBody = `{"data":[{"recent":"42"}]}`
			} else if strings.Contains(q, "countIf") || strings.Contains(bodyStr, "countIf") {
				respBody = `{"data":[{"total":"100","blocked":"15"}]}`
			} else if strings.Contains(q, "SELECT count()") || strings.Contains(bodyStr, "SELECT count()") {
				respBody = `{"data":[{"count()":"42"}]}`
			} else if strings.Contains(q, "SELECT event_id") || strings.Contains(bodyStr, "SELECT event_id") {
				queryReceived.Add(1)
				respBody = `{"data":[{"event_id":"evt-100","timestamp":"2026-10-19 10:00:00.000","host":"example.com","action":"block","rule_id":"SEMANTIC_SQLI","country":"US"}]}`
			} else if strings.Contains(q, "GROUP BY country") || strings.Contains(bodyStr, "GROUP BY country") {
				respBody = `{"data":[{"country":"US","cnt":"10"},{"country":"CN","cnt":"5"}]}`
			} else if strings.Contains(q, "GROUP BY rule_id") || strings.Contains(bodyStr, "GROUP BY rule_id") {
				respBody = `{"data":[{"rule_id":"SQLI","cnt":"8"}]}`
			} else if strings.Contains(q, "GROUP BY client_ip") || strings.Contains(bodyStr, "GROUP BY client_ip") {
				respBody = `{"data":[{"client_ip":"1.2.3.4","cnt":"4"}]}`
			} else if strings.Contains(q, "GROUP BY attack_category") || strings.Contains(bodyStr, "GROUP BY attack_category") {
				respBody = `{"data":[{"attack_category":"sql_inj","cnt":"6"}]}`
			} else if strings.Contains(q, "GROUP BY bucket") || strings.Contains(bodyStr, "GROUP BY bucket") {
				respBody = `{"data":[{"bucket":"2026-10-19 10:00:00","total":"50","blocked":"8"}]}`
			} else if strings.Contains(q, "ALTER TABLE") || strings.Contains(bodyStr, "ALTER TABLE") {
				respBody = "OK"
			} else {
				respBody = "OK"
			}

			return &http.Response{
				StatusCode: statusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
			}, nil
		}),
	}

	store, err := NewClickHouseStore(ClickHouseConfig{
		URL:        "http://clickhouse.internal:8123",
		HTTPClient: mockClient,
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	events := []*telemetry.ForensicEvent{
		{
			EventID:   "evt-1",
			Timestamp: time.Now(),
			ClientIP:  "127.0.0.1",
			Action:    "block",
		},
	}
	if err := store.SaveBatch(ctx, events); err != nil {
		t.Fatalf("save batch failed: %v", err)
	}
	if batchReceived.Load() != 1 {
		t.Errorf("expected 1 batch received, got %d", batchReceived.Load())
	}

	res, err := store.Query(ctx, telemetry.QueryParams{
		Action: "block",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if res.Total != 42 {
		t.Errorf("expected total 42, got %d", res.Total)
	}
	if len(res.Events) != 1 || res.Events[0].EventID != "evt-100" {
		t.Errorf("unexpected event result: %+v", res.Events)
	}

	stats, err := store.QueryAggregates(ctx, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("query aggregates failed: %v", err)
	}
	if stats.TotalRequests != 100 || stats.TotalBlocked != 15 {
		t.Errorf("unexpected totals: %+v", stats)
	}
	if stats.PageViews != 70 || stats.UniqueIPs != 12 || stats.UniqueVisitors != 12 || stats.BlockedIPs != 4 {
		t.Errorf("unexpected traffic fields: %+v", stats)
	}
	if stats.Status4xx != 20 || stats.Status4xxBlocked != 15 || stats.Status5xx != 2 {
		t.Errorf("unexpected status fields: %+v", stats)
	}
	if stats.BlockRatio != 0.15 || stats.Status4xxRate != 0.2 || stats.Status4xxBlockRate != 0.15 || stats.Status5xxRate != 0.02 {
		t.Errorf("unexpected rates: %+v", stats)
	}
	if stats.QPS != 4.2 {
		t.Errorf("expected QPS 4.2, got %f", stats.QPS)
	}
	if len(stats.TopCountries) != 2 {
		t.Errorf("expected 2 top countries, got %d", len(stats.TopCountries))
	}
	if len(stats.TopCategories) != 1 || stats.TopCategories[0].Key != "sql_inj" {
		t.Errorf("unexpected top categories: %+v", stats.TopCategories)
	}
	if len(stats.TimeBuckets) != 1 {
		t.Errorf("expected 1 time bucket, got %d", len(stats.TimeBuckets))
	}

	_, err = store.Prune(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
}

func TestClickHouseStore_RetryOnTransientError(t *testing.T) {
	var attempts atomic.Int32

	mockClient := &http.Client{
		Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
			att := attempts.Add(1)
			if att < 3 {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewBufferString("transient error")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString("OK")),
			}, nil
		}),
	}

	store, err := NewClickHouseStore(ClickHouseConfig{
		URL:        "http://clickhouse.internal:8123",
		MaxRetries: 3,
		HTTPClient: mockClient,
	})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	events := []*telemetry.ForensicEvent{{EventID: "evt-retry", Timestamp: time.Now()}}
	if err := store.SaveBatch(ctx, events); err != nil {
		t.Fatalf("expected success after retries, got err: %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestClickHouseWhereFilters(t *testing.T) {
	base := clickHouseWhere("2026-10-26 10:00:00.000", "2026-10-26 11:00:00.000")
	want := "timestamp >= '2026-10-26 10:00:00.000' AND timestamp <= '2026-10-26 11:00:00.000'"
	if base != want {
		t.Fatalf("unexpected base where clause: %s", base)
	}

	filtered := clickHouseWhere("a", "b", telemetry.AggregateFilter{
		Host:    "app.example.com",
		Country: `O'Reilly\Labs`,
	})
	wantFiltered := "timestamp >= 'a' AND timestamp <= 'b' AND host = 'app.example.com' AND country = 'O\\'Reilly\\\\Labs'"
	if filtered != wantFiltered {
		t.Fatalf("unexpected filtered where clause:\n got %s\nwant %s", filtered, wantFiltered)
	}
}

func TestParseClickHouseBucket(t *testing.T) {
	cases := map[string]time.Time{
		"2026-10-26 10:00:00.000": time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC),
		"2026-10-26 10:00:00":     time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC),
		"2026-10-26T10:00:00Z":    time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC),
	}
	for raw, want := range cases {
		if got := parseClickHouseBucket(raw); !got.Equal(want) {
			t.Errorf("parseClickHouseBucket(%q) = %v, want %v", raw, got, want)
		}
	}
}
