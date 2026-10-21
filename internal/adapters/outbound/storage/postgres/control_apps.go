package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Apps

func (s *ControlStore) ListApps(ctx context.Context) ([]control.SiteApp, error) {
	query := `SELECT id, name, hostnames, mode, upstreams, block_status_code, block_response_body,
	                 offline_status_code, offline_response_body, custom_headers, proxy_settings, created_at, updated_at
	          FROM raiwall_apps ORDER BY name ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	defer rows.Close()

	var apps []control.SiteApp
	for rows.Next() {
		var a control.SiteApp
		err := rows.Scan(
			&a.ID, &a.Name, &a.Hostnames, &a.Mode, &a.Upstreams,
			&a.BlockStatusCode, &a.BlockResponseBody,
			&a.OfflineStatusCode, &a.OfflineResponseBody,
			&a.CustomHeaders, &a.ProxySettings, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan app: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func (s *ControlStore) GetApp(ctx context.Context, id string) (control.SiteApp, error) {
	query := `SELECT id, name, hostnames, mode, upstreams, block_status_code, block_response_body,
	                 offline_status_code, offline_response_body, custom_headers, proxy_settings, created_at, updated_at
	          FROM raiwall_apps WHERE id = $1 LIMIT 1`
	var a control.SiteApp
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&a.ID, &a.Name, &a.Hostnames, &a.Mode, &a.Upstreams,
		&a.BlockStatusCode, &a.BlockResponseBody,
		&a.OfflineStatusCode, &a.OfflineResponseBody,
		&a.CustomHeaders, &a.ProxySettings, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return control.SiteApp{}, fmt.Errorf("get app %s: %w", id, err)
	}
	return a, nil
}

func (s *ControlStore) CreateApp(ctx context.Context, app control.SiteApp) error {
	query := `INSERT INTO raiwall_apps (
		id, name, hostnames, mode, upstreams, block_status_code, block_response_body,
		offline_status_code, offline_response_body, custom_headers, proxy_settings, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err := s.db.ExecContext(ctx, query,
		app.ID, app.Name, app.Hostnames, app.Mode, app.Upstreams,
		app.BlockStatusCode, app.BlockResponseBody,
		app.OfflineStatusCode, app.OfflineResponseBody,
		app.CustomHeaders, app.ProxySettings, app.CreatedAt, app.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateApp(ctx context.Context, app control.SiteApp) error {
	query := `UPDATE raiwall_apps SET
		name = $1, hostnames = $2, mode = $3, upstreams = $4, block_status_code = $5,
		block_response_body = $6, offline_status_code = $7, offline_response_body = $8,
		custom_headers = $9, proxy_settings = $10, updated_at = $11
	WHERE id = $12`
	_, err := s.db.ExecContext(ctx, query,
		app.Name, app.Hostnames, app.Mode, app.Upstreams,
		app.BlockStatusCode, app.BlockResponseBody,
		app.OfflineStatusCode, app.OfflineResponseBody,
		app.CustomHeaders, app.ProxySettings, app.UpdatedAt,
		app.ID,
	)
	return err
}

func (s *ControlStore) DeleteApp(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_apps WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
