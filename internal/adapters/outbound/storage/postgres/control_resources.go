package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// API Resources

func (s *ControlStore) ListAPIResourcesByApp(ctx context.Context, appID string) ([]control.ApiResourceRecord, error) {
	query := `SELECT id, app_id, method, path_pattern, content_type, hit_count, last_seen, created_at
	          FROM raiwall_api_resources WHERE app_id = $1 ORDER BY hit_count DESC, last_seen DESC`
	rows, err := s.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("list api resources: %w", err)
	}
	defer rows.Close()

	var list []control.ApiResourceRecord
	for rows.Next() {
		var a control.ApiResourceRecord
		if err := rows.Scan(&a.ID, &a.AppID, &a.Method, &a.PathPattern, &a.ContentType, &a.HitCount, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api resource: %w", err)
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetAPIResource(ctx context.Context, id string) (control.ApiResourceRecord, error) {
	query := `SELECT id, app_id, method, path_pattern, content_type, hit_count, last_seen, created_at
	          FROM raiwall_api_resources WHERE id = $1 LIMIT 1`
	var a control.ApiResourceRecord
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&a.ID, &a.AppID, &a.Method, &a.PathPattern, &a.ContentType, &a.HitCount, &a.LastSeen, &a.CreatedAt,
	)
	if err != nil {
		return control.ApiResourceRecord{}, fmt.Errorf("get api resource %s: %w", id, err)
	}
	return a, nil
}

func (s *ControlStore) UpsertAPIResource(ctx context.Context, res control.ApiResourceRecord) error {
	query := `INSERT INTO raiwall_api_resources (
		id, app_id, method, path_pattern, content_type, hit_count, last_seen, created_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (app_id, method, path_pattern) DO UPDATE SET
		hit_count = raiwall_api_resources.hit_count + EXCLUDED.hit_count,
		content_type = CASE WHEN EXCLUDED.content_type != '' THEN EXCLUDED.content_type ELSE raiwall_api_resources.content_type END,
		last_seen = EXCLUDED.last_seen`
	_, err := s.db.ExecContext(ctx, query,
		res.ID, res.AppID, res.Method, res.PathPattern, res.ContentType,
		res.HitCount, res.LastSeen, res.CreatedAt,
	)
	return err
}

func (s *ControlStore) DeleteAPIResource(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_api_resources WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *ControlStore) DeleteAPIResourcesByApp(ctx context.Context, appID string) error {
	query := `DELETE FROM raiwall_api_resources WHERE app_id = $1`
	_, err := s.db.ExecContext(ctx, query, appID)
	return err
}
