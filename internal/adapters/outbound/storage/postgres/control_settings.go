package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Portal-wide key/value settings.

func (s *ControlStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM raiwall_settings WHERE key = $1", key).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("get setting %s: %w", key, err)
	}
	return value, nil
}

func (s *ControlStore) PutSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_settings (key, value, updated_at)
		VALUES ($1,$2,$3)
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`,
		key, value, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("put setting %s: %w", key, err)
	}
	return nil
}

// Authentication audit log.

func (s *ControlStore) RecordIdentityAuthEvent(ctx context.Context, event control.IdentityAuthEventRecord) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_identity_auth_log
		(created_at, username, app_id, host, method, result, client_ip, country, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (created_at, username, result) DO UPDATE SET
		app_id=EXCLUDED.app_id, host=EXCLUDED.host, method=EXCLUDED.method,
		client_ip=EXCLUDED.client_ip, country=EXCLUDED.country, detail=EXCLUDED.detail`,
		event.CreatedAt, event.Username, event.AppID, event.Host, event.Method, event.Result,
		event.ClientIP, event.Country, event.Detail)
	if err != nil {
		return fmt.Errorf("record identity auth event: %w", err)
	}
	return nil
}

func (s *ControlStore) ListIdentityAuthEvents(ctx context.Context, limit int) ([]control.IdentityAuthEventRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT created_at, username, app_id, host, method, result, client_ip, country, detail FROM raiwall_identity_auth_log ORDER BY created_at DESC LIMIT $1",
		limit)
	if err != nil {
		return nil, fmt.Errorf("list identity auth events: %w", err)
	}
	defer rows.Close()

	result := make([]control.IdentityAuthEventRecord, 0)
	for rows.Next() {
		var e control.IdentityAuthEventRecord
		if err := rows.Scan(&e.CreatedAt, &e.Username, &e.AppID, &e.Host, &e.Method,
			&e.Result, &e.ClientIP, &e.Country, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan identity auth event: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
