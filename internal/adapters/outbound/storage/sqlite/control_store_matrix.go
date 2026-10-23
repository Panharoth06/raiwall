package sqlite

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Semantic Detector Matrix (global module modes)

func (s *Store) ListDetectorConfig(ctx context.Context) ([]control.DetectorConfigRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT module, mode, updated_at FROM raiwall_detector_config ORDER BY module ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.DetectorConfigRecord
	for rows.Next() {
		var r control.DetectorConfigRecord
		if err := rows.Scan(&r.Module, &r.Mode, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) UpsertDetectorConfig(ctx context.Context, cfg control.DetectorConfigRecord) error {
	if cfg.UpdatedAt.IsZero() {
		cfg.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_detector_config (module, mode, updated_at) VALUES (?, ?, ?)",
		cfg.Module, cfg.Mode, cfg.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteDetectorConfig(ctx context.Context, module string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_detector_config WHERE module = ?", module)
	return err
}

// Per-Application Semantic Policy Overrides

func (s *Store) ListAppSemanticPolicies(ctx context.Context) ([]control.AppSemanticPolicyRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT app_id, policy, updated_at FROM raiwall_app_semantic_policies ORDER BY app_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.AppSemanticPolicyRecord
	for rows.Next() {
		var r control.AppSemanticPolicyRecord
		if err := rows.Scan(&r.AppID, &r.Policy, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) UpsertAppSemanticPolicy(ctx context.Context, rec control.AppSemanticPolicyRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_app_semantic_policies (app_id, policy, updated_at) VALUES (?, ?, ?)",
		rec.AppID, rec.Policy, rec.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteAppSemanticPolicy(ctx context.Context, appID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_app_semantic_policies WHERE app_id = ?", appID)
	return err
}
