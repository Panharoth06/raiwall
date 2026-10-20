package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SQLiteStore implements ForensicStore backed by an embedded SQLite database in WAL mode.
type SQLiteStore struct {
	db        *sql.DB
	stopCh    chan struct{}
	wg        sync.WaitGroup
	retention time.Duration
}

// SQLiteConfig holds options for creating an SQLiteStore.
type SQLiteConfig struct {
	DSN          string
	Retention    time.Duration
	PruneInterval time.Duration
}

// NewSQLiteStore opens or creates an SQLite database at dsn and initializes schema.
func NewSQLiteStore(cfg SQLiteConfig) (*SQLiteStore, error) {
	dsn := cfg.DSN
	if dsn == "" {
		dsn = "file:raiwall_forensics.db?_pragma=busy_timeout(5000)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Recommended connection pooling for SQLite WAL
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Set pragmas for performance and concurrency
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA foreign_keys = ON;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("exec pragma %s: %w", pragma, err)
		}
	}

	store := &SQLiteStore{
		db:        db,
		stopCh:    make(chan struct{}),
		retention: cfg.Retention,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}

	if cfg.Retention > 0 {
		pruneInterval := cfg.PruneInterval
		if pruneInterval <= 0 {
			pruneInterval = time.Hour
		}
		store.startRetentionWorker(cfg.Retention, pruneInterval)
	}

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS forensic_events (
		event_id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		host TEXT,
		path TEXT,
		method TEXT,
		client_ip TEXT,
		ja4 TEXT,
		country TEXT,
		continent TEXT,
		city TEXT,
		asn INTEGER,
		as_org TEXT,
		latitude REAL,
		longitude REAL,
		rule_id TEXT,
		action TEXT,
		severity TEXT,
		headers TEXT,
		payload TEXT,
		latency_us INTEGER,
		status_code INTEGER,
		payload_location TEXT,
		matched_token TEXT,
		attack_category TEXT,
		response_headers TEXT,
		response_body BLOB
	);

	CREATE INDEX IF NOT EXISTS idx_events_ts ON forensic_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_ip ON forensic_events(client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_action ON forensic_events(action);
	CREATE INDEX IF NOT EXISTS idx_events_rule ON forensic_events(rule_id);
	CREATE INDEX IF NOT EXISTS idx_events_country ON forensic_events(country);
	CREATE INDEX IF NOT EXISTS idx_events_composite ON forensic_events(timestamp, action, rule_id, client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_ip_host_ts ON forensic_events(client_ip, host, timestamp);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	migrations := []string{
		"ALTER TABLE forensic_events ADD COLUMN payload_location TEXT;",
		"ALTER TABLE forensic_events ADD COLUMN matched_token TEXT;",
		"ALTER TABLE forensic_events ADD COLUMN attack_category TEXT;",
		"ALTER TABLE forensic_events ADD COLUMN response_headers TEXT;",
		"ALTER TABLE forensic_events ADD COLUMN response_body BLOB;",
	}
	for _, m := range migrations {
		_, _ = s.db.Exec(m)
	}
	return nil
}

func (s *SQLiteStore) startRetentionWorker(retention, interval time.Duration) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, _ = s.Prune(ctx, retention)
				cancel()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// SaveBatch writes an array of forensic events in a single transaction.
func (s *SQLiteStore) SaveBatch(ctx context.Context, events []*ForensicEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
	INSERT OR REPLACE INTO forensic_events (
		event_id, timestamp, host, path, method, client_ip, ja4,
		country, continent, city, asn, as_org, latitude, longitude,
		rule_id, action, severity, headers, payload, latency_us, status_code,
		payload_location, matched_token, attack_category, response_headers, response_body
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		var headersJSON, respHeadersJSON string
		if len(e.Headers) > 0 {
			if b, err := json.Marshal(e.Headers); err == nil {
				headersJSON = string(b)
			}
		}
		if len(e.ResponseHeaders) > 0 {
			if b, err := json.Marshal(e.ResponseHeaders); err == nil {
				respHeadersJSON = string(b)
			}
		}

		_, err := stmt.ExecContext(ctx,
			e.EventID,
			e.Timestamp.UTC().Format(time.RFC3339Nano),
			e.Host,
			e.Path,
			e.Method,
			e.ClientIP,
			e.JA4,
			e.GeoData.Country,
			e.GeoData.Continent,
			e.GeoData.City,
			e.GeoData.ASN,
			e.GeoData.ASOrg,
			e.GeoData.Latitude,
			e.GeoData.Longitude,
			e.RuleID,
			e.Action,
			e.Severity,
			headersJSON,
			e.TruncatedPayload,
			e.Latency.Microseconds(),
			e.StatusCode,
			e.PayloadLocation,
			e.MatchedToken,
			e.AttackCategory,
			respHeadersJSON,
			e.ResponseBody,
		)
		if err != nil {
			return fmt.Errorf("exec insert event %s: %w", e.EventID, err)
		}
	}

	return tx.Commit()
}

// Query performs a filtered, paginated query across stored forensic events.
func (s *SQLiteStore) Query(ctx context.Context, params QueryParams) (*QueryResult, error) {
	whereClauses := []string{"1=1"}
	args := []interface{}{}

	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, params.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, params.EndTime.UTC().Format(time.RFC3339Nano))
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, "client_ip = ?")
		args = append(args, params.ClientIP)
	}
	if params.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, params.Action)
	}
	if params.RuleID != "" {
		whereClauses = append(whereClauses, "rule_id = ?")
		args = append(args, params.RuleID)
	}
	if params.Country != "" {
		whereClauses = append(whereClauses, "country = ?")
		args = append(args, params.Country)
	}
	if params.MinSeverity != "" {
		whereClauses = append(whereClauses, "severity = ?")
		args = append(args, params.MinSeverity)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// 1. Get total matching count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM forensic_events WHERE %s", whereSQL)
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count query: %w", err)
	}

	// 2. Fetch page of events
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchQuery := fmt.Sprintf(`
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code,
		       COALESCE(payload_location, '') AS payload_location,
		       COALESCE(matched_token, '') AS matched_token,
		       COALESCE(attack_category, '') AS attack_category,
		       COALESCE(response_headers, '') AS response_headers,
		       COALESCE(response_body, '') AS response_body
		FROM forensic_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("fetch query: %w", err)
	}
	defer rows.Close()

	var events []*ForensicEvent
	for rows.Next() {
		var (
			e               ForensicEvent
			tsStr           string
			headersJSON     string
			respHeadersJSON string
			latencyUs       int64
		)
		err := rows.Scan(
			&e.EventID,
			&tsStr,
			&e.Host,
			&e.Path,
			&e.Method,
			&e.ClientIP,
			&e.JA4,
			&e.GeoData.Country,
			&e.GeoData.Continent,
			&e.GeoData.City,
			&e.GeoData.ASN,
			&e.GeoData.ASOrg,
			&e.GeoData.Latitude,
			&e.GeoData.Longitude,
			&e.RuleID,
			&e.Action,
			&e.Severity,
			&headersJSON,
			&e.TruncatedPayload,
			&latencyUs,
			&e.StatusCode,
			&e.PayloadLocation,
			&e.MatchedToken,
			&e.AttackCategory,
			&respHeadersJSON,
			&e.ResponseBody,
		)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}

		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			e.Timestamp = t
		}
		if headersJSON != "" {
			_ = json.Unmarshal([]byte(headersJSON), &e.Headers)
		}
		if respHeadersJSON != "" {
			_ = json.Unmarshal([]byte(respHeadersJSON), &e.ResponseHeaders)
		}
		e.Latency = time.Duration(latencyUs) * time.Microsecond
		events = append(events, &e)
	}

	return &QueryResult{
		Events: events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// QueryAggregates computes summary metrics and top aggregations across a time interval.
func (s *SQLiteStore) QueryAggregates(ctx context.Context, start, end time.Time) (*AggregateStats, error) {
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now()
	}

	startStr := start.UTC().Format(time.RFC3339Nano)
	endStr := end.UTC().Format(time.RFC3339Nano)

	stats := &AggregateStats{
		TimeBuckets:  make([]TimeBucketCount, 0),
		TopCountries: make([]TopCount, 0),
		TopRules:     make([]TopCount, 0),
		TopIPs:       make([]TopCount, 0),
	}

	// 1. Total & Blocked count
	totalQuery := `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END), 0)
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ?
	`
	if err := s.db.QueryRowContext(ctx, totalQuery, startStr, endStr).Scan(&stats.TotalRequests, &stats.TotalBlocked); err != nil {
		return nil, fmt.Errorf("query totals: %w", err)
	}

	if stats.TotalRequests > 0 {
		stats.BlockRatio = float64(stats.TotalBlocked) / float64(stats.TotalRequests)
	}

	// 2. Top Countries
	countryQuery := `
		SELECT country, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ? AND country != ''
		GROUP BY country
		ORDER BY cnt DESC
		LIMIT 10
	`
	cRows, err := s.db.QueryContext(ctx, countryQuery, startStr, endStr)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var tc TopCount
			if err := cRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopCountries = append(stats.TopCountries, tc)
			}
		}
	}

	// 3. Top Rules
	ruleQuery := `
		SELECT rule_id, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ? AND rule_id != ''
		GROUP BY rule_id
		ORDER BY cnt DESC
		LIMIT 10
	`
	rRows, err := s.db.QueryContext(ctx, ruleQuery, startStr, endStr)
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var tc TopCount
			if err := rRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopRules = append(stats.TopRules, tc)
			}
		}
	}

	// 4. Top IPs
	ipQuery := `
		SELECT client_ip, COUNT(*) as cnt
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ? AND client_ip != ''
		GROUP BY client_ip
		ORDER BY cnt DESC
		LIMIT 10
	`
	ipRows, err := s.db.QueryContext(ctx, ipQuery, startStr, endStr)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var tc TopCount
			if err := ipRows.Scan(&tc.Key, &tc.Count); err == nil {
				stats.TopIPs = append(stats.TopIPs, tc)
			}
		}
	}

	// 5. Time Buckets (grouped by hour or 5 minutes)
	bucketQuery := `
		SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as bucket,
		       COUNT(*) as total,
		       SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END) as blocked
		FROM forensic_events
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY bucket
		ORDER BY bucket ASC
	`
	bRows, err := s.db.QueryContext(ctx, bucketQuery, startStr, endStr)
	if err == nil {
		defer bRows.Close()
		for bRows.Next() {
			var (
				bucketStr string
				total     int64
				blocked   int64
			)
			if err := bRows.Scan(&bucketStr, &total, &blocked); err == nil {
				if t, err := time.Parse(time.RFC3339, bucketStr); err == nil {
					stats.TimeBuckets = append(stats.TimeBuckets, TimeBucketCount{
						Bucket: t,
						Total:  total,
						Block:  blocked,
					})
				}
			}
		}
	}

	return stats, nil
}

// Prune deletes records older than maxAge.
func (s *SQLiteStore) Prune(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, "DELETE FROM forensic_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	return res.RowsAffected()
}

// Close terminates background retention loops and closes the SQLite database connection.
func (s *SQLiteStore) Close() error {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
	return s.db.Close()
}

// GetEventByID retrieves a single forensic event by its unique UUID.
func (s *SQLiteStore) GetEventByID(ctx context.Context, eventID string) (*ForensicEvent, error) {
	query := `
		SELECT event_id, timestamp, host, path, method, client_ip, ja4,
		       country, continent, city, asn, as_org, latitude, longitude,
		       rule_id, action, severity, headers, payload, latency_us, status_code,
		       COALESCE(payload_location, ''), COALESCE(matched_token, ''),
		       COALESCE(attack_category, ''), COALESCE(response_headers, ''),
		       COALESCE(response_body, X'')
		FROM forensic_events
		WHERE event_id = ?
		LIMIT 1
	`
	row := s.db.QueryRowContext(ctx, query, eventID)
	var (
		e               ForensicEvent
		tsStr           string
		headersJSON     string
		respHeadersJSON string
		latencyUs       int64
	)
	err := row.Scan(
		&e.EventID, &tsStr, &e.Host, &e.Path, &e.Method, &e.ClientIP, &e.JA4,
		&e.GeoData.Country, &e.GeoData.Continent, &e.GeoData.City, &e.GeoData.ASN, &e.GeoData.ASOrg,
		&e.GeoData.Latitude, &e.GeoData.Longitude,
		&e.RuleID, &e.Action, &e.Severity, &headersJSON, &e.TruncatedPayload,
		&latencyUs, &e.StatusCode,
		&e.PayloadLocation, &e.MatchedToken, &e.AttackCategory,
		&respHeadersJSON, &e.ResponseBody,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get event by id %s: %w", eventID, err)
	}

	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		e.Timestamp = t
	}
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &e.Headers)
	}
	if respHeadersJSON != "" {
		_ = json.Unmarshal([]byte(respHeadersJSON), &e.ResponseHeaders)
	}
	e.Latency = time.Duration(latencyUs) * time.Microsecond
	return &e, nil
}

// GetAggregatedIncidents groups events occurring within a sliding 5-minute window by client_ip and host.
func (s *SQLiteStore) GetAggregatedIncidents(ctx context.Context, params IncidentQueryParams) (*IncidentQueryResult, error) {
	whereClauses := []string{"1=1"}
	args := []interface{}{}

	if !params.StartTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, params.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !params.EndTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, params.EndTime.UTC().Format(time.RFC3339Nano))
	}
	if params.ClientIP != "" {
		whereClauses = append(whereClauses, "client_ip = ?")
		args = append(args, params.ClientIP)
	}
	if params.Host != "" {
		whereClauses = append(whereClauses, "host = ?")
		args = append(args, params.Host)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			SELECT 1 FROM forensic_events
			WHERE %s
			GROUP BY client_ip, host, (CAST(strftime('%%%%s', timestamp) AS INTEGER) / 300)
		)
	`, whereSQL)

	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("incident count query: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	fetchQuery := fmt.Sprintf(`
		SELECT 
			client_ip,
			host,
			(CAST(strftime('%%%%s', timestamp) AS INTEGER) / 300) as time_window,
			MIN(timestamp) as min_ts,
			MAX(timestamp) as max_ts,
			COUNT(*) as total_events,
			SUM(CASE WHEN action IN ('block', 'ban') THEN 1 ELSE 0 END) as total_blocked,
			MAX(severity) as max_severity,
			MAX(rule_id) as top_rule,
			COALESCE(MAX(attack_category), '') as category,
			COALESCE(MAX(country), '') as country
		FROM forensic_events
		WHERE %s
		GROUP BY client_ip, host, time_window
		ORDER BY min_ts DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, fetchQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("fetch incidents query: %w", err)
	}
	defer rows.Close()

	var incidents []*Incident
	for rows.Next() {
		var (
			inc        Incident
			timeWindow int64
			minTsStr   string
			maxTsStr   string
		)
		err := rows.Scan(
			&inc.ClientIP,
			&inc.Host,
			&timeWindow,
			&minTsStr,
			&maxTsStr,
			&inc.TotalEvents,
			&inc.TotalBlocked,
			&inc.MaxSeverity,
			&inc.TopRuleID,
			&inc.Category,
			&inc.Country,
		)
		if err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}

		if t, err := time.Parse(time.RFC3339Nano, minTsStr); err == nil {
			inc.StartTime = t
		}
		if t, err := time.Parse(time.RFC3339Nano, maxTsStr); err == nil {
			inc.EndTime = t
		}
		inc.ID = fmt.Sprintf("inc-%s-%s-%d", inc.ClientIP, inc.Host, timeWindow)
		if inc.Category == "" {
			inc.Category = inc.TopRuleID
		}
		incidents = append(incidents, &inc)
	}

	return &IncidentQueryResult{
		Incidents:  incidents,
		TotalCount: total,
	}, nil
}
