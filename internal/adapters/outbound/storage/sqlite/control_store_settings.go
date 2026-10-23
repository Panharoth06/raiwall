package sqlite

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Portal-wide key/value settings (session secrets, portal branding).

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM raiwall_settings WHERE key = ?", key).Scan(&value)
	return value, err
}

func (s *Store) PutSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_settings (key, value, updated_at) VALUES (?, ?, ?)",
		key, value, time.Now().UTC())
	return err
}

// Authentication audit log (Task 93 logs tab data source).

func (s *Store) RecordIdentityAuthEvent(ctx context.Context, event control.IdentityAuthEventRecord) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_identity_auth_log (created_at, username, app_id, host, method, result, client_ip, country, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		event.CreatedAt, event.Username, event.AppID, event.Host, event.Method, event.Result,
		event.ClientIP, event.Country, event.Detail)
	return err
}

func (s *Store) ListIdentityAuthEvents(ctx context.Context, limit int) ([]control.IdentityAuthEventRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT created_at, username, app_id, host, method, result, client_ip, country, detail FROM raiwall_identity_auth_log ORDER BY created_at DESC LIMIT ?",
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]control.IdentityAuthEventRecord, 0)
	for rows.Next() {
		var e control.IdentityAuthEventRecord
		if err := rows.Scan(&e.CreatedAt, &e.Username, &e.AppID, &e.Host, &e.Method,
			&e.Result, &e.ClientIP, &e.Country, &e.Detail); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
