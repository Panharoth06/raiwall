package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
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
	URL        string        // e.g. "http://localhost:8123"
	Database   string        // default "default"
	Table      string        // default "raiwall_forensic_events"
	Username   string        // optional username
	Password   string        // optional password
	Timeout    time.Duration // default 5s
	MaxRetries int           // default 3
	HTTPClient *http.Client  // optional custom client
}

// ClickHouseStore implements ForensicStore for enterprise columnar log analytics.
type ClickHouseStore struct {
	url        string
	database   string
	table      string
	username   string
	password   string
	maxRetries int
	client     *http.Client
}

// NewClickHouseStore constructs a ClickHouseStore and ensures table schema.
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

	store := &ClickHouseStore{
		url:        baseURL,
		database:   db,
		table:      table,
		username:   cfg.Username,
		password:   cfg.Password,
		maxRetries: retries,
		client:     httpClient,
	}

	return store, nil
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

// InitSchema automatically runs the schema migration on the ClickHouse cluster.
func (s *ClickHouseStore) InitSchema(ctx context.Context) error {
	_, err := s.execWithRetry(ctx, s.TableSchemaDDL(), nil)
	return err
}

// SaveBatch persists a batch of events using native high-performance JSONEachRow streaming.
func (s *ClickHouseStore) SaveBatch(ctx context.Context, events []*ForensicEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, e := range events {
		var headersStr string
		if len(e.Headers) > 0 {
			if b, err := json.Marshal(e.Headers); err == nil {
				headersStr = string(b)
			}
		}

		record := map[string]interface{}{
			"event_id":    e.EventID,
			"timestamp":   e.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			"host":        e.Host,
			"path":        e.Path,
			"method":      e.Method,
			"client_ip":   e.ClientIP,
			"ja4":         e.JA4,
			"country":     e.GeoData.Country,
			"continent":   e.GeoData.Continent,
			"city":        e.GeoData.City,
			"asn":         e.GeoData.ASN,
			"as_org":      e.GeoData.ASOrg,
			"latitude":    e.GeoData.Latitude,
			"longitude":   e.GeoData.Longitude,
			"rule_id":     e.RuleID,
			"action":      e.Action,
			"severity":    e.Severity,
			"headers":     headersStr,
			"payload":     e.TruncatedPayload,
			"latency_us":  e.Latency.Microseconds(),
			"status_code": e.StatusCode,
		}

		line, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal ch record: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", s.database, s.table)
	_, err := s.execWithRetry(ctx, query, &buf)
	return err
}

// Query performs a filtered historical query in ClickHouse.
func (s *ClickHouseStore) Query(ctx context.Context, params QueryParams) (*QueryResult, error) {
	whereClauses := []string{"1=1"}
	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp >= '%s'", params.StartTime.UTC().Format("2006-01-02 15:04:05.000")))
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp <= '%s'", params.EndTime.UTC().Format("2006-01-02 15:04:05.000")))
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("client_ip = '%s'", escapeCH(params.ClientIP)))
	}
	if params.Action != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("action = '%s'", escapeCH(params.Action)))
	}
	if params.RuleID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("rule_id = '%s'", escapeCH(params.RuleID)))
	}
	if params.Country != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("country = '%s'", escapeCH(params.Country)))
	}
	if params.MinSeverity != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("severity = '%s'", escapeCH(params.MinSeverity)))
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// 1. Count query
	countSQL := fmt.Sprintf("SELECT count() FROM %s.%s WHERE %s FORMAT JSON", s.database, s.table, whereSQL)
	countResp, err := s.execWithRetry(ctx, countSQL, nil)
	if err != nil {
		return nil, fmt.Errorf("count query: %w", err)
	}

	var countData struct {
		Data []struct {
			Count string `json:"count()"`
		} `json:"data"`
	}
	_ = json.Unmarshal(countResp, &countData)
	var total int64
	if len(countData.Data) > 0 {
		fmt.Sscanf(countData.Data[0].Count, "%d", &total)
	}

	// 2. Fetch page
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchSQL := fmt.Sprintf(`
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code
		FROM %s.%s
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d
		FORMAT JSON
	`, s.database, s.table, whereSQL, limit, offset)

	fetchResp, err := s.execWithRetry(ctx, fetchSQL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch query: %w", err)
	}

	var queryData struct {
		Data []struct {
			EventID    string  `json:"event_id"`
			Timestamp  string  `json:"timestamp"`
			Host       string  `json:"host"`
			Path       string  `json:"path"`
			Method     string  `json:"method"`
			ClientIP   string  `json:"client_ip"`
			JA4        string  `json:"ja4"`
			Country    string  `json:"country"`
			Continent  string  `json:"continent"`
			City       string  `json:"city"`
			ASN        uint    `json:"asn"`
			ASOrg      string  `json:"as_org"`
			Latitude   float64 `json:"latitude"`
			Longitude  float64 `json:"longitude"`
			RuleID     string  `json:"rule_id"`
			Action     string  `json:"action"`
			Severity   string  `json:"severity"`
			Headers    string  `json:"headers"`
			Payload    string  `json:"payload"`
			LatencyUs  int64   `json:"latency_us"`
			StatusCode int     `json:"status_code"`
		} `json:"data"`
	}
	_ = json.Unmarshal(fetchResp, &queryData)

	events := make([]*ForensicEvent, 0, len(queryData.Data))
	for _, row := range queryData.Data {
		ts, _ := time.Parse("2006-01-02 15:04:05.000", row.Timestamp)
		var hMap map[string]string
		if row.Headers != "" {
			_ = json.Unmarshal([]byte(row.Headers), &hMap)
		}

		events = append(events, &ForensicEvent{
			EventID:   row.EventID,
			Timestamp: ts,
			Host:      row.Host,
			Path:      row.Path,
			Method:    row.Method,
			ClientIP:  row.ClientIP,
			JA4:       row.JA4,
			GeoData: GeoData{
				Country:   row.Country,
				Continent: row.Continent,
				City:      row.City,
				ASN:       row.ASN,
				ASOrg:     row.ASOrg,
				Latitude:  row.Latitude,
				Longitude: row.Longitude,
			},
			RuleID:           row.RuleID,
			Action:           row.Action,
			Severity:         row.Severity,
			Headers:          hMap,
			TruncatedPayload: row.Payload,
			Latency:          time.Duration(row.LatencyUs) * time.Microsecond,
			StatusCode:       row.StatusCode,
		})
	}

	return &QueryResult{
		Events: events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// QueryAggregates computes summary metrics and top distributions in ClickHouse.
func (s *ClickHouseStore) QueryAggregates(ctx context.Context, start, end time.Time) (*AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startStr := start.UTC().Format("2006-01-02 15:04:05.000")
	endStr := end.UTC().Format("2006-01-02 15:04:05.000")

	stats := &AggregateStats{
		TimeBuckets:  make([]TimeBucketCount, 0),
		TopCountries: make([]TopCount, 0),
		TopRules:     make([]TopCount, 0),
		TopIPs:       make([]TopCount, 0),
	}

	// 1. Totals
	totalSQL := fmt.Sprintf(`
		SELECT count() as total,
		       countIf(action IN ('block', 'ban')) as blocked
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s'
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)

	resp, err := s.execWithRetry(ctx, totalSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil && len(d.Data) > 0 {
			fmt.Sscanf(d.Data[0].Total, "%d", &stats.TotalRequests)
			fmt.Sscanf(d.Data[0].Blocked, "%d", &stats.TotalBlocked)
			if stats.TotalRequests > 0 {
				stats.BlockRatio = float64(stats.TotalBlocked) / float64(stats.TotalRequests)
			}
		}
	}

	// 2. Top Countries
	countrySQL := fmt.Sprintf(`
		SELECT country, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, countrySQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Country string `json:"country"`
				Cnt     string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopCountries = append(stats.TopCountries, TopCount{Key: r.Country, Count: count})
			}
		}
	}

	// 3. Top Rules
	ruleSQL := fmt.Sprintf(`
		SELECT rule_id, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, ruleSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				RuleID string `json:"rule_id"`
				Cnt    string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopRules = append(stats.TopRules, TopCount{Key: r.RuleID, Count: count})
			}
		}
	}

	// 4. Top IPs
	ipSQL := fmt.Sprintf(`
		SELECT client_ip, count() as cnt
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s' AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, ipSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				ClientIP string `json:"client_ip"`
				Cnt      string `json:"cnt"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var count int64
				fmt.Sscanf(r.Cnt, "%d", &count)
				stats.TopIPs = append(stats.TopIPs, TopCount{Key: r.ClientIP, Count: count})
			}
		}
	}

	// 5. Time Buckets
	bucketSQL := fmt.Sprintf(`
		SELECT toStartOfHour(timestamp) as bucket,
		       count() as total,
		       countIf(action IN ('block', 'ban')) as blocked
		FROM %s.%s
		WHERE timestamp >= '%s' AND timestamp <= '%s'
		GROUP BY bucket
		ORDER BY bucket ASC
		FORMAT JSON
	`, s.database, s.table, startStr, endStr)
	resp, err = s.execWithRetry(ctx, bucketSQL, nil)
	if err == nil {
		var d struct {
			Data []struct {
				Bucket  string `json:"bucket"`
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			} `json:"data"`
		}
		if json.Unmarshal(resp, &d) == nil {
			for _, r := range d.Data {
				var total, blocked int64
				fmt.Sscanf(r.Total, "%d", &total)
				fmt.Sscanf(r.Blocked, "%d", &blocked)
				t, err := time.Parse("2006-01-02 15:04:05", r.Bucket)
				if err != nil {
					t, _ = time.Parse(time.RFC3339, r.Bucket)
				}
				stats.TimeBuckets = append(stats.TimeBuckets, TimeBucketCount{
					Bucket: t,
					Total:  total,
					Block:  blocked,
				})
			}
		}
	}

	return stats, nil
}

// Prune issues a lightweight ALTER TABLE DELETE command to delete expired partitions.
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
