package clickhouse

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultClickHouseTable = "raiwall_forensic_events"
)

// ClickHouseConfig specifies connection and behavior settings for ClickHouseStore.
type ClickHouseConfig struct {
	URL        string
	Database   string
	Table      string
	Username   string
	Password   string
	Timeout    time.Duration
	MaxRetries int
	HTTPClient *http.Client
}

// ClickHouseStore implements telemetry.ForensicStore for columnar analytics.
type ClickHouseStore struct {
	url        string
	database   string
	table      string
	username   string
	password   string
	maxRetries int
	client     *http.Client
}

// NewClickHouseStore constructs a ClickHouseStore.
func NewClickHouseStore(cfg ClickHouseConfig) (*ClickHouseStore, error) {
	baseURL := cfg.URL
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8123"
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	db := cfg.Database
	if db == "" {
		db = "default"
	}

	table := cfg.Table
	if table == "" {
		table = DefaultClickHouseTable
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	retries := cfg.MaxRetries
	if retries <= 0 {
		retries = 3
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
		}
	}

	return &ClickHouseStore{
		url:        baseURL,
		database:   db,
		table:      table,
		username:   cfg.Username,
		password:   cfg.Password,
		maxRetries: retries,
		client:     httpClient,
	}, nil
}

// TableSchemaDDL returns the standard MergeTree DDL for forensic logs.
func (s *ClickHouseStore) TableSchemaDDL() string {
	return fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s.%s (
		event_id String,
		timestamp DateTime64(3, 'UTC'),
		host LowCardinality(String),
		path String,
		method LowCardinality(String),
		client_ip String,
		ja4 String,
		country LowCardinality(String),
		continent LowCardinality(String),
		city String,
		asn UInt32,
		as_org String,
		latitude Float64,
		longitude Float64,
		rule_id LowCardinality(String),
		action LowCardinality(String),
		severity LowCardinality(String),
		headers String,
		payload String CODEC(ZSTD(1)),
		latency_us UInt64,
		status_code UInt16
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMMDD(timestamp)
	ORDER BY (timestamp, action, rule_id, client_ip)
	SETTINGS index_granularity = 8192;
	`, s.database, s.table)
}

// InitSchema automatically runs schema creation on ClickHouse.
func (s *ClickHouseStore) InitSchema(ctx context.Context) error {
	_, err := s.execWithRetry(ctx, s.TableSchemaDDL(), nil)
	return err
}

// Prune issues a lightweight ALTER TABLE DELETE command.
func (s *ClickHouseStore) Prune(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format("2006-01-02 15:04:05.000")
	query := fmt.Sprintf("ALTER TABLE %s.%s DELETE WHERE timestamp < '%s'", s.database, s.table, cutoff)
	_, err := s.execWithRetry(ctx, query, nil)
	return 0, err
}

// Close closes any persistent connections.
func (s *ClickHouseStore) Close() error {
	s.client.CloseIdleConnections()
	return nil
}

func (s *ClickHouseStore) execWithRetry(ctx context.Context, query string, body io.Reader) ([]byte, error) {
	var lastErr error
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = io.ReadAll(body)
	}

	for attempt := 0; attempt < s.maxRetries; attempt++ {
		reqURL := fmt.Sprintf("%s/?database=%s", s.url, url.QueryEscape(s.database))
		var rBody io.Reader
		if len(bodyBytes) > 0 {
			rBody = bytes.NewReader(bodyBytes)
			reqURL += "&query=" + url.QueryEscape(query)
		} else {
			rBody = strings.NewReader(query)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, rBody)
		if err != nil {
			return nil, err
		}

		if s.username != "" || s.password != "" {
			req.SetBasicAuth(s.username, s.password)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt*50) * time.Millisecond)
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBytes, nil
		}

		lastErr = fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, string(respBytes))
		if resp.StatusCode >= 500 {
			time.Sleep(time.Duration(attempt*50) * time.Millisecond)
			continue
		}
		break
	}

	return nil, lastErr
}

func escapeCH(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
