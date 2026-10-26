package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// TelemetryStore implements telemetry.ForensicStore backed by SQLite WAL mode.
type TelemetryStore struct {
	db        *sql.DB
	ownsDB    bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	retention time.Duration
}

// TelemetryConfig holds configuration options for TelemetryStore.
type TelemetryConfig struct {
	DSN           string
	Retention     time.Duration
	PruneInterval time.Duration
}

// SQLiteConfig is an alias for backwards compatibility.
type SQLiteConfig = TelemetryConfig

// NewTelemetryStore opens or creates an SQLite database at dsn and initializes schema.
func NewTelemetryStore(cfg TelemetryConfig) (*TelemetryStore, error) {
	dsn := cfg.DSN
	if dsn == "" {
		dsn = "file:raiwall_forensics.db?_pragma=busy_timeout(5000)"
	}

	if err := prepareSQLiteDSN(dsn); err != nil {
		return nil, fmt.Errorf("prepare sqlite database %q: %w", dsn, err)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

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

	store := &TelemetryStore{
		db:        db,
		ownsDB:    true,
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

// NewSQLiteStore provides a backwards-compatible constructor for TelemetryStore.
func NewSQLiteStore(cfg TelemetryConfig) (*TelemetryStore, error) {
	return NewTelemetryStore(cfg)
}

// NewTelemetryStoreFromDB wraps an existing database connection pool for telemetry.
func NewTelemetryStoreFromDB(db *sql.DB, retention, pruneInterval time.Duration) (*TelemetryStore, error) {
	store := &TelemetryStore{
		db:        db,
		ownsDB:    false,
		stopCh:    make(chan struct{}),
		retention: retention,
	}

	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}

	if retention > 0 {
		if pruneInterval <= 0 {
			pruneInterval = time.Hour
		}
		store.startRetentionWorker(retention, pruneInterval)
	}

	return store, nil
}

func (s *TelemetryStore) initSchema() error {
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

func (s *TelemetryStore) startRetentionWorker(retention, interval time.Duration) {
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
func (s *TelemetryStore) SaveBatch(ctx context.Context, events []*telemetry.ForensicEvent) error {
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

// Prune deletes records older than maxAge.
func (s *TelemetryStore) Prune(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, "DELETE FROM forensic_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	return res.RowsAffected()
}

// Close terminates background retention loops and closes the SQLite database connection if owned.
func (s *TelemetryStore) Close() error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
	if s.ownsDB && s.db != nil {
		return s.db.Close()
	}
	return nil
}
