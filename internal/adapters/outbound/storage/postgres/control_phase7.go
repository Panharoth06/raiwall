package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// IP Groups

func (s *ControlStore) ListIPGroups(ctx context.Context) ([]control.IPGroupRecord, error) {
	query := `SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list ip groups: %w", err)
	}
	defer rows.Close()

	var result []control.IPGroupRecord
	for rows.Next() {
		var g control.IPGroupRecord
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan ip group: %w", err)
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetIPGroup(ctx context.Context, id string) (control.IPGroupRecord, error) {
	query := `SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups WHERE id = $1 LIMIT 1`
	var g control.IPGroupRecord
	err := s.db.QueryRowContext(ctx, query, id).Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return control.IPGroupRecord{}, fmt.Errorf("get ip group: %w", err)
	}
	return g, nil
}

func (s *ControlStore) GetIPGroupByName(ctx context.Context, name string) (control.IPGroupRecord, error) {
	query := `SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups WHERE name = $1 LIMIT 1`
	var g control.IPGroupRecord
	err := s.db.QueryRowContext(ctx, query, name).Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return control.IPGroupRecord{}, fmt.Errorf("get ip group by name: %w", err)
	}
	return g, nil
}

func (s *ControlStore) CreateIPGroup(ctx context.Context, group control.IPGroupRecord) error {
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}
	query := `INSERT INTO raiwall_ip_groups (id, name, description, type, created_at, updated_at)
	          VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.db.ExecContext(ctx, query, group.ID, group.Name, group.Description, group.Type, group.CreatedAt, group.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create ip group: %w", err)
	}
	return nil
}

func (s *ControlStore) UpdateIPGroup(ctx context.Context, group control.IPGroupRecord) error {
	group.UpdatedAt = time.Now().UTC()
	query := `UPDATE raiwall_ip_groups SET name = $1, description = $2, type = $3, updated_at = $4 WHERE id = $5`
	_, err := s.db.ExecContext(ctx, query, group.Name, group.Description, group.Type, group.UpdatedAt, group.ID)
	if err != nil {
		return fmt.Errorf("update ip group: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteIPGroup(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_ip_groups WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete ip group: %w", err)
	}
	return nil
}

func (s *ControlStore) ListIPGroupEntries(ctx context.Context, groupID string) ([]control.IPGroupEntryRecord, error) {
	query := `SELECT id, group_id, cidr_or_ip, comment, created_at FROM raiwall_ip_group_entries WHERE group_id = $1 ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("list ip group entries: %w", err)
	}
	defer rows.Close()

	var result []control.IPGroupEntryRecord
	for rows.Next() {
		var e control.IPGroupEntryRecord
		if err := rows.Scan(&e.ID, &e.GroupID, &e.CIDR, &e.Comment, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ip group entry: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *ControlStore) CreateIPGroupEntry(ctx context.Context, entry control.IPGroupEntryRecord) error {
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	query := `INSERT INTO raiwall_ip_group_entries (id, group_id, cidr_or_ip, comment, created_at)
	          VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.ExecContext(ctx, query, entry.ID, entry.GroupID, entry.CIDR, entry.Comment, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("create ip group entry: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteIPGroupEntry(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_ip_group_entries WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete ip group entry: %w", err)
	}
	return nil
}

// Response Templates

func (s *ControlStore) ListTemplates(ctx context.Context) ([]control.TemplateRecord, error) {
	query := `SELECT id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at
	          FROM raiwall_response_templates ORDER BY status_code ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()

	var result []control.TemplateRecord
	for rows.Next() {
		var t control.TemplateRecord
		if err := rows.Scan(&t.ID, &t.StatusCode, &t.Title, &t.ContentHTML, &t.CustomCSS, &t.BrandName, &t.LogoURL, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		result = append(result, t)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetTemplate(ctx context.Context, statusCode int) (control.TemplateRecord, error) {
	query := `SELECT id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at
	          FROM raiwall_response_templates WHERE status_code = $1 LIMIT 1`
	var t control.TemplateRecord
	err := s.db.QueryRowContext(ctx, query, statusCode).Scan(
		&t.ID, &t.StatusCode, &t.Title, &t.ContentHTML, &t.CustomCSS, &t.BrandName, &t.LogoURL, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return control.TemplateRecord{}, fmt.Errorf("get template: %w", err)
	}
	return t, nil
}

func (s *ControlStore) UpsertTemplate(ctx context.Context, tmpl control.TemplateRecord) error {
	now := time.Now().UTC()
	if tmpl.CreatedAt.IsZero() {
		tmpl.CreatedAt = now
	}
	tmpl.UpdatedAt = now
	query := `INSERT INTO raiwall_response_templates (id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	          ON CONFLICT (status_code) DO UPDATE SET
	            title = EXCLUDED.title, content_html = EXCLUDED.content_html,
	            custom_css = EXCLUDED.custom_css, brand_name = EXCLUDED.brand_name,
	            logo_url = EXCLUDED.logo_url, is_custom = EXCLUDED.is_custom, updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query, tmpl.ID, tmpl.StatusCode, tmpl.Title, tmpl.ContentHTML, tmpl.CustomCSS, tmpl.BrandName, tmpl.LogoURL, tmpl.IsCustom, tmpl.CreatedAt, tmpl.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert template: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteTemplate(ctx context.Context, statusCode int) error {
	query := `DELETE FROM raiwall_response_templates WHERE status_code = $1`
	_, err := s.db.ExecContext(ctx, query, statusCode)
	if err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	return nil
}
