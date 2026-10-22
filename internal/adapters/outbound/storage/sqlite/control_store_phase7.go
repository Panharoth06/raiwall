package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// IP Groups

func (s *Store) ListIPGroups(ctx context.Context) ([]control.IPGroupRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.IPGroupRecord
	for rows.Next() {
		var g control.IPGroupRecord
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

func (s *Store) GetIPGroup(ctx context.Context, id string) (control.IPGroupRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups WHERE id = ?", id)
	var g control.IPGroupRecord
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return control.IPGroupRecord{}, fmt.Errorf("ip group %q not found", id)
		}
		return control.IPGroupRecord{}, err
	}
	return g, nil
}

func (s *Store) GetIPGroupByName(ctx context.Context, name string) (control.IPGroupRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT id, name, description, type, created_at, updated_at FROM raiwall_ip_groups WHERE name = ?", name)
	var g control.IPGroupRecord
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Type, &g.CreatedAt, &g.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return control.IPGroupRecord{}, fmt.Errorf("ip group %q not found", name)
		}
		return control.IPGroupRecord{}, err
	}
	return g, nil
}

func (s *Store) CreateIPGroup(ctx context.Context, group control.IPGroupRecord) error {
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO raiwall_ip_groups (id, name, description, type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		group.ID, group.Name, group.Description, group.Type, group.CreatedAt, group.UpdatedAt,
	)
	return err
}

func (s *Store) UpdateIPGroup(ctx context.Context, group control.IPGroupRecord) error {
	group.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		"UPDATE raiwall_ip_groups SET name = ?, description = ?, type = ?, updated_at = ? WHERE id = ?",
		group.Name, group.Description, group.Type, group.UpdatedAt, group.ID,
	)
	return err
}

func (s *Store) DeleteIPGroup(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_ip_groups WHERE id = ?", id)
	return err
}

func (s *Store) ListIPGroupEntries(ctx context.Context, groupID string) ([]control.IPGroupEntryRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, group_id, cidr_or_ip, comment, created_at FROM raiwall_ip_group_entries WHERE group_id = ? ORDER BY created_at ASC", groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.IPGroupEntryRecord
	for rows.Next() {
		var e control.IPGroupEntryRecord
		if err := rows.Scan(&e.ID, &e.GroupID, &e.CIDR, &e.Comment, &e.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *Store) CreateIPGroupEntry(ctx context.Context, entry control.IPGroupEntryRecord) error {
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO raiwall_ip_group_entries (id, group_id, cidr_or_ip, comment, created_at) VALUES (?, ?, ?, ?, ?)",
		entry.ID, entry.GroupID, entry.CIDR, entry.Comment, entry.CreatedAt,
	)
	return err
}

func (s *Store) DeleteIPGroupEntry(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_ip_group_entries WHERE id = ?", id)
	return err
}

// Response Templates

func (s *Store) ListTemplates(ctx context.Context) ([]control.TemplateRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at FROM raiwall_response_templates ORDER BY status_code ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.TemplateRecord
	for rows.Next() {
		var t control.TemplateRecord
		if err := rows.Scan(&t.ID, &t.StatusCode, &t.Title, &t.ContentHTML, &t.CustomCSS, &t.BrandName, &t.LogoURL, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, rows.Err()
}

func (s *Store) GetTemplate(ctx context.Context, statusCode int) (control.TemplateRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at FROM raiwall_response_templates WHERE status_code = ?", statusCode)
	var t control.TemplateRecord
	if err := row.Scan(&t.ID, &t.StatusCode, &t.Title, &t.ContentHTML, &t.CustomCSS, &t.BrandName, &t.LogoURL, &t.IsCustom, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return control.TemplateRecord{}, fmt.Errorf("template for status %d not found", statusCode)
		}
		return control.TemplateRecord{}, err
	}
	return t, nil
}

func (s *Store) UpsertTemplate(ctx context.Context, tmpl control.TemplateRecord) error {
	now := time.Now().UTC()
	if tmpl.CreatedAt.IsZero() {
		tmpl.CreatedAt = now
	}
	tmpl.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO raiwall_response_templates (id, status_code, title, content_html, custom_css, brand_name, logo_url, is_custom, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		tmpl.ID, tmpl.StatusCode, tmpl.Title, tmpl.ContentHTML, tmpl.CustomCSS, tmpl.BrandName, tmpl.LogoURL, tmpl.IsCustom, tmpl.CreatedAt, tmpl.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteTemplate(ctx context.Context, statusCode int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_response_templates WHERE status_code = ?", statusCode)
	return err
}
