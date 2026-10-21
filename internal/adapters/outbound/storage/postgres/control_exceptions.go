package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Exceptions

func (s *ControlStore) ListExceptions(ctx context.Context) ([]control.ExceptionRule, error) {
	query := `SELECT id, description, host, path_regex, path_prefix, method, location,
	                 param_name, param_regex, rule_id, is_active, created_at, updated_at
	          FROM raiwall_exceptions ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	defer rows.Close()

	var list []control.ExceptionRule
	for rows.Next() {
		var e control.ExceptionRule
		err := rows.Scan(
			&e.ID, &e.Description, &e.Host, &e.PathRegex, &e.PathPrefix,
			&e.Method, &e.Location, &e.ParamName, &e.ParamRegex,
			&e.RuleID, &e.IsActive, &e.CreatedAt, &e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan exception: %w", err)
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListActiveExceptions(ctx context.Context) ([]control.ExceptionRule, error) {
	query := `SELECT id, description, host, path_regex, path_prefix, method, location,
	                 param_name, param_regex, rule_id, is_active, created_at, updated_at
	          FROM raiwall_exceptions WHERE is_active = 1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active exceptions: %w", err)
	}
	defer rows.Close()

	var list []control.ExceptionRule
	for rows.Next() {
		var e control.ExceptionRule
		err := rows.Scan(
			&e.ID, &e.Description, &e.Host, &e.PathRegex, &e.PathPrefix,
			&e.Method, &e.Location, &e.ParamName, &e.ParamRegex,
			&e.RuleID, &e.IsActive, &e.CreatedAt, &e.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan active exception: %w", err)
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetException(ctx context.Context, id string) (control.ExceptionRule, error) {
	query := `SELECT id, description, host, path_regex, path_prefix, method, location,
	                 param_name, param_regex, rule_id, is_active, created_at, updated_at
	          FROM raiwall_exceptions WHERE id = $1 LIMIT 1`
	var e control.ExceptionRule
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&e.ID, &e.Description, &e.Host, &e.PathRegex, &e.PathPrefix,
		&e.Method, &e.Location, &e.ParamName, &e.ParamRegex,
		&e.RuleID, &e.IsActive, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return control.ExceptionRule{}, fmt.Errorf("get exception %s: %w", id, err)
	}
	return e, nil
}

func (s *ControlStore) CreateException(ctx context.Context, exc control.ExceptionRule) error {
	query := `INSERT INTO raiwall_exceptions (
		id, description, host, path_regex, path_prefix, method, location,
		param_name, param_regex, rule_id, is_active, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err := s.db.ExecContext(ctx, query,
		exc.ID, exc.Description, exc.Host, exc.PathRegex, exc.PathPrefix,
		exc.Method, exc.Location, exc.ParamName, exc.ParamRegex,
		exc.RuleID, exc.IsActive, exc.CreatedAt, exc.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateException(ctx context.Context, exc control.ExceptionRule) error {
	query := `UPDATE raiwall_exceptions SET
		description = $1, host = $2, path_regex = $3, path_prefix = $4, method = $5,
		location = $6, param_name = $7, param_regex = $8, rule_id = $9, is_active = $10,
		updated_at = $11
	WHERE id = $12`
	_, err := s.db.ExecContext(ctx, query,
		exc.Description, exc.Host, exc.PathRegex, exc.PathPrefix, exc.Method,
		exc.Location, exc.ParamName, exc.ParamRegex, exc.RuleID, exc.IsActive,
		exc.UpdatedAt, exc.ID,
	)
	return err
}

func (s *ControlStore) DeleteException(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_exceptions WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
