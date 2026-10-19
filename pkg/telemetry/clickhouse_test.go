package telemetry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

	// 1. SaveBatch
	events := []*ForensicEvent{
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

	// 2. Query
	res, err := store.Query(ctx, QueryParams{
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

	// 3. QueryAggregates
	stats, err := store.QueryAggregates(ctx, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("query aggregates failed: %v", err)
	}
	if stats.TotalRequests != 100 || stats.TotalBlocked != 15 {
		t.Errorf("unexpected totals: %+v", stats)
	}
	if len(stats.TopCountries) != 2 {
		t.Errorf("expected 2 top countries, got %d", len(stats.TopCountries))
	}
	if len(stats.TimeBuckets) != 1 {
		t.Errorf("expected 1 time bucket, got %d", len(stats.TimeBuckets))
	}

	// 4. Prune
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
	events := []*ForensicEvent{{EventID: "evt-retry", Timestamp: time.Now()}}
	if err := store.SaveBatch(ctx, events); err != nil {
		t.Fatalf("expected success after retries, got err: %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}
