package sqlite

import (
	"context"
	"time"
)

// Inner Rules (virtual-patch signature toggles): a row's presence marks the
// rule as disabled; absence enables it (bundled default).

func (s *Store) ListDisabledInnerRules(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT rule_id FROM raiwall_inner_rule_disabled ORDER BY rule_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Store) SetInnerRuleDisabled(ctx context.Context, ruleID string, disabled bool) error {
	if disabled {
		_, err := s.db.ExecContext(ctx,
			"INSERT OR REPLACE INTO raiwall_inner_rule_disabled (rule_id, updated_at) VALUES (?, ?)",
			ruleID, time.Now().UTC(),
		)
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_inner_rule_disabled WHERE rule_id = ?", ruleID)
	return err
}

func (s *Store) ClearDisabledInnerRules(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_inner_rule_disabled")
	return err
}
