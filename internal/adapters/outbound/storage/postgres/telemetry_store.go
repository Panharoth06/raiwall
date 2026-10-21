package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// TelemetryStore implements telemetry.ForensicStore backed by PostgreSQL.
type TelemetryStore struct {
	db        *sql.DB
	ownsDB    bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	retention time.Duration
}

var _ telemetry.ForensicStore = (*TelemetryStore)(nil)

// NewTelemetryStore initializes a new TelemetryStore using a shared db pool.
func NewTelemetryStore(db *sql.DB, retention, pruneInterval time.Duration) *TelemetryStore {
	return newTelemetryStore(db, retention, pruneInterval, false)
}

// NewStandaloneTelemetryStore initializes a TelemetryStore that owns and closes db.
func NewStandaloneTelemetryStore(db *sql.DB, retention, pruneInterval time.Duration) *TelemetryStore {
	return newTelemetryStore(db, retention, pruneInterval, true)
}

func newTelemetryStore(db *sql.DB, retention, pruneInterval time.Duration, ownsDB bool) *TelemetryStore {
	store := &TelemetryStore{
		db:        db,
		ownsDB:    ownsDB,
		stopCh:    make(chan struct{}),
		retention: retention,
	}

	if retention > 0 {
		if pruneInterval <= 0 {
			pruneInterval = time.Hour
		}
		store.startRetentionWorker(retention, pruneInterval)
	}

	return store
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
		return fmt.Errorf("begin postgres batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
	INSERT INTO forensic_events (
		event_id, timestamp, host, path, method, client_ip, ja4,
		country, continent, city, asn, as_org, latitude, longitude,
		rule_id, action, severity, headers, payload, latency_us, status_code,
		payload_location, matched_token, attack_category, response_headers, response_body
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
	) ON CONFLICT (event_id) DO UPDATE SET
		timestamp = EXCLUDED.timestamp,
		host = EXCLUDED.host,
		path = EXCLUDED.path,
		method = EXCLUDED.method,
		client_ip = EXCLUDED.client_ip,
		ja4 = EXCLUDED.ja4,
		country = EXCLUDED.country,
		continent = EXCLUDED.continent,
		city = EXCLUDED.city,
		asn = EXCLUDED.asn,
		as_org = EXCLUDED.as_org,
		latitude = EXCLUDED.latitude,
		longitude = EXCLUDED.longitude,
		rule_id = EXCLUDED.rule_id,
		action = EXCLUDED.action,
		severity = EXCLUDED.severity,
		headers = EXCLUDED.headers,
		payload = EXCLUDED.payload,
		latency_us = EXCLUDED.latency_us,
		status_code = EXCLUDED.status_code,
		payload_location = EXCLUDED.payload_location,
		matched_token = EXCLUDED.matched_token,
		attack_category = EXCLUDED.attack_category,
		response_headers = EXCLUDED.response_headers,
		response_body = EXCLUDED.response_body
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("prepare postgres insert: %w", err)
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
			e.Timestamp.UTC(),
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
			return fmt.Errorf("insert postgres event %s: %w", e.EventID, err)
		}
	}

	return tx.Commit()
}

// Prune deletes records older than maxAge.
func (s *TelemetryStore) Prune(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC()
	res, err := s.db.ExecContext(ctx, "DELETE FROM forensic_events WHERE timestamp < $1", cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune postgres events: %w", err)
	}
	return res.RowsAffected()
}

// Close terminates background retention loops and releases pool connections if owned.
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
