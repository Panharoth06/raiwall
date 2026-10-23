package postgres

import (
	"context"
	"fmt"
	"time"
)

// Inner Rules (virtual-patch signature toggles): a row's presence marks the
// rule as disabled; absence enables it (bundled default).

func (s *ControlStore) ListDisabledInnerRules(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT rule_id FROM raiwall_inner_rule_disabled ORDER BY rule_id ASC")
	if err != nil {
		return nil, fmt.Errorf("list disabled inner rules: %w", err)
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan disabled inner rules: %w", err)
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *ControlStore) SetInnerRuleDisabled(ctx context.Context, ruleID string, disabled bool) error {
	if disabled {
		_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_inner_rule_disabled (rule_id, updated_at)
			VALUES ($1, $2) ON CONFLICT (rule_id) DO NOTHING`,
			ruleID, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("disable inner rule: %w", err)
		}
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_inner_rule_disabled WHERE rule_id = $1", ruleID); err != nil {
		return fmt.Errorf("enable inner rule: %w", err)
	}
	return nil
}

func (s *ControlStore) ClearDisabledInnerRules(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_inner_rule_disabled"); err != nil {
		return fmt.Errorf("clear disabled inner rules: %w", err)
	}
	return nil
}
