package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Forwarding Rules

func (s *ControlStore) ListForwardingRules(ctx context.Context) ([]control.ForwardingRuleRecord, error) {
	query := `SELECT id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	          FROM raiwall_forwarding_rules ORDER BY prefix ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list forwarding rules: %w", err)
	}
	defer rows.Close()

	var list []control.ForwardingRuleRecord
	for rows.Next() {
		var f control.ForwardingRuleRecord
		if err := rows.Scan(&f.ID, &f.AppID, &f.Prefix, &f.Upstreams, &f.StripPrefix, &f.HostHeaderOverride, &f.Comment, &f.IsActive, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan forwarding rule: %w", err)
		}
		list = append(list, f)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListForwardingRulesByApp(ctx context.Context, appID string) ([]control.ForwardingRuleRecord, error) {
	query := `SELECT id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	          FROM raiwall_forwarding_rules WHERE app_id = $1 ORDER BY prefix ASC`
	rows, err := s.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("list forwarding rules by app: %w", err)
	}
	defer rows.Close()

	var list []control.ForwardingRuleRecord
	for rows.Next() {
		var f control.ForwardingRuleRecord
		if err := rows.Scan(&f.ID, &f.AppID, &f.Prefix, &f.Upstreams, &f.StripPrefix, &f.HostHeaderOverride, &f.Comment, &f.IsActive, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan forwarding rule: %w", err)
		}
		list = append(list, f)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListActiveForwardingRulesByApp(ctx context.Context, appID string) ([]control.ForwardingRuleRecord, error) {
	query := `SELECT id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	          FROM raiwall_forwarding_rules WHERE app_id = $1 AND is_active = 1 ORDER BY prefix ASC`
	rows, err := s.db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("list active forwarding rules by app: %w", err)
	}
	defer rows.Close()

	var list []control.ForwardingRuleRecord
	for rows.Next() {
		var f control.ForwardingRuleRecord
		if err := rows.Scan(&f.ID, &f.AppID, &f.Prefix, &f.Upstreams, &f.StripPrefix, &f.HostHeaderOverride, &f.Comment, &f.IsActive, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan active forwarding rule: %w", err)
		}
		list = append(list, f)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListAllActiveForwardingRules(ctx context.Context) ([]control.ForwardingRuleRecord, error) {
	query := `SELECT id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	          FROM raiwall_forwarding_rules WHERE is_active = 1 ORDER BY prefix ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all active forwarding rules: %w", err)
	}
	defer rows.Close()

	var list []control.ForwardingRuleRecord
	for rows.Next() {
		var f control.ForwardingRuleRecord
		if err := rows.Scan(&f.ID, &f.AppID, &f.Prefix, &f.Upstreams, &f.StripPrefix, &f.HostHeaderOverride, &f.Comment, &f.IsActive, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan all active forwarding rules: %w", err)
		}
		list = append(list, f)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetForwardingRule(ctx context.Context, id string) (control.ForwardingRuleRecord, error) {
	query := `SELECT id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	          FROM raiwall_forwarding_rules WHERE id = $1 LIMIT 1`
	var f control.ForwardingRuleRecord
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&f.ID, &f.AppID, &f.Prefix, &f.Upstreams, &f.StripPrefix, &f.HostHeaderOverride, &f.Comment, &f.IsActive, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return control.ForwardingRuleRecord{}, fmt.Errorf("get forwarding rule %s: %w", id, err)
	}
	return f, nil
}

func (s *ControlStore) CreateForwardingRule(ctx context.Context, rule control.ForwardingRuleRecord) error {
	query := `INSERT INTO raiwall_forwarding_rules (
		id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := s.db.ExecContext(ctx, query,
		rule.ID, rule.AppID, rule.Prefix, rule.Upstreams, rule.StripPrefix,
		rule.HostHeaderOverride, rule.Comment, rule.IsActive, rule.CreatedAt, rule.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateForwardingRule(ctx context.Context, rule control.ForwardingRuleRecord) error {
	query := `UPDATE raiwall_forwarding_rules SET
		prefix = $1, upstreams = $2, strip_prefix = $3, host_header_override = $4,
		comment = $5, is_active = $6, updated_at = $7
	WHERE id = $8`
	_, err := s.db.ExecContext(ctx, query,
		rule.Prefix, rule.Upstreams, rule.StripPrefix, rule.HostHeaderOverride,
		rule.Comment, rule.IsActive, rule.UpdatedAt, rule.ID,
	)
	return err
}

func (s *ControlStore) DeleteForwardingRule(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_forwarding_rules WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

func (s *ControlStore) DeleteForwardingRulesByApp(ctx context.Context, appID string) error {
	query := `DELETE FROM raiwall_forwarding_rules WHERE app_id = $1`
	_, err := s.db.ExecContext(ctx, query, appID)
	return err
}
