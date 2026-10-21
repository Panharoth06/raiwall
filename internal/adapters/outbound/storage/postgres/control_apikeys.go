package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// API Keys

func (s *ControlStore) ListAPIKeys(ctx context.Context) ([]control.ApiKeyRecord, error) {
	query := `SELECT id, name, key_hash, role, expires_at, is_active, created_at, last_used_at
	          FROM raiwall_api_keys ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var list []control.ApiKeyRecord
	for rows.Next() {
		var k control.ApiKeyRecord
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.Role, &k.ExpiresAt, &k.IsActive, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetAPIKeyByID(ctx context.Context, id string) (control.ApiKeyRecord, error) {
	query := `SELECT id, name, key_hash, role, expires_at, is_active, created_at, last_used_at
	          FROM raiwall_api_keys WHERE id = $1 LIMIT 1`
	var k control.ApiKeyRecord
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&k.ID, &k.Name, &k.KeyHash, &k.Role, &k.ExpiresAt, &k.IsActive, &k.CreatedAt, &k.LastUsedAt,
	)
	if err != nil {
		return control.ApiKeyRecord{}, fmt.Errorf("get api key %s: %w", id, err)
	}
	return k, nil
}

func (s *ControlStore) GetAPIKeyByHash(ctx context.Context, keyHash string) (control.ApiKeyRecord, error) {
	query := `SELECT id, name, key_hash, role, expires_at, is_active, created_at, last_used_at
	          FROM raiwall_api_keys WHERE key_hash = $1 AND is_active = 1 LIMIT 1`
	var k control.ApiKeyRecord
	err := s.db.QueryRowContext(ctx, query, keyHash).Scan(
		&k.ID, &k.Name, &k.KeyHash, &k.Role, &k.ExpiresAt, &k.IsActive, &k.CreatedAt, &k.LastUsedAt,
	)
	if err != nil {
		return control.ApiKeyRecord{}, fmt.Errorf("get api key by hash: %w", err)
	}
	return k, nil
}

func (s *ControlStore) CreateAPIKey(ctx context.Context, key control.ApiKeyRecord) error {
	query := `INSERT INTO raiwall_api_keys (id, name, key_hash, role, expires_at, is_active, created_at, last_used_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.db.ExecContext(ctx, query,
		key.ID, key.Name, key.KeyHash, key.Role, key.ExpiresAt, key.IsActive, key.CreatedAt, key.LastUsedAt,
	)
	return err
}

func (s *ControlStore) UpdateAPIKeyLastUsed(ctx context.Context, id string, lastUsedAt time.Time) error {
	query := `UPDATE raiwall_api_keys SET last_used_at = $1 WHERE id = $2`
	var val sql.NullTime
	if !lastUsedAt.IsZero() {
		val = sql.NullTime{Time: lastUsedAt, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, query, val, id)
	return err
}

func (s *ControlStore) DeleteAPIKey(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_api_keys WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
