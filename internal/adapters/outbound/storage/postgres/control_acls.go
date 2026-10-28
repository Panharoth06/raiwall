package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// ACL Rules

func (s *ControlStore) ListACLRules(ctx context.Context) ([]control.AclRule, error) {
	query := `SELECT id, name, expression, action, priority, status_code, redirect_url, is_active, continue_inspection, created_at, updated_at
	          FROM raiwall_acl_rules ORDER BY priority DESC, created_at ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list acl rules: %w", err)
	}
	defer rows.Close()

	var list []control.AclRule
	for rows.Next() {
		var r control.AclRule
		err := rows.Scan(
			&r.ID, &r.Name, &r.Expression, &r.Action, &r.Priority,
			&r.StatusCode, &r.RedirectUrl, &r.IsActive, &r.ContinueInspection, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan acl rule: %w", err)
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListActiveACLRules(ctx context.Context) ([]control.AclRule, error) {
	query := `SELECT id, name, expression, action, priority, status_code, redirect_url, is_active, continue_inspection, created_at, updated_at
	          FROM raiwall_acl_rules WHERE is_active = 1 ORDER BY priority DESC, created_at ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active acl rules: %w", err)
	}
	defer rows.Close()

	var list []control.AclRule
	for rows.Next() {
		var r control.AclRule
		err := rows.Scan(
			&r.ID, &r.Name, &r.Expression, &r.Action, &r.Priority,
			&r.StatusCode, &r.RedirectUrl, &r.IsActive, &r.ContinueInspection, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan active acl rule: %w", err)
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetACLRule(ctx context.Context, id string) (control.AclRule, error) {
	query := `SELECT id, name, expression, action, priority, status_code, redirect_url, is_active, continue_inspection, created_at, updated_at
	          FROM raiwall_acl_rules WHERE id = $1 LIMIT 1`
	var r control.AclRule
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&r.ID, &r.Name, &r.Expression, &r.Action, &r.Priority,
		&r.StatusCode, &r.RedirectUrl, &r.IsActive, &r.ContinueInspection, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return control.AclRule{}, fmt.Errorf("get acl rule %s: %w", id, err)
	}
	return r, nil
}

func (s *ControlStore) CreateACLRule(ctx context.Context, rule control.AclRule) error {
	query := `INSERT INTO raiwall_acl_rules (
		id, name, expression, action, priority, status_code, redirect_url, is_active, continue_inspection, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := s.db.ExecContext(ctx, query,
		rule.ID, rule.Name, rule.Expression, rule.Action, rule.Priority,
		rule.StatusCode, rule.RedirectUrl, rule.IsActive, rule.ContinueInspection, rule.CreatedAt, rule.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateACLRule(ctx context.Context, rule control.AclRule) error {
	query := `UPDATE raiwall_acl_rules SET
		name = $1, expression = $2, action = $3, priority = $4, status_code = $5,
		redirect_url = $6, is_active = $7, continue_inspection = $8, updated_at = $9
	WHERE id = $10`
	_, err := s.db.ExecContext(ctx, query,
		rule.Name, rule.Expression, rule.Action, rule.Priority, rule.StatusCode,
		rule.RedirectUrl, rule.IsActive, rule.ContinueInspection, rule.UpdatedAt, rule.ID,
	)
	return err
}

func (s *ControlStore) DeleteACLRule(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_acl_rules WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
