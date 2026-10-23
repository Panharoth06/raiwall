package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Semantic Detector Matrix (global module modes)

func (s *ControlStore) ListDetectorConfig(ctx context.Context) ([]control.DetectorConfigRecord, error) {
	query := `SELECT module, mode, updated_at FROM raiwall_detector_config ORDER BY module ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list detector config: %w", err)
	}
	defer rows.Close()

	var result []control.DetectorConfigRecord
	for rows.Next() {
		var r control.DetectorConfigRecord
		if err := rows.Scan(&r.Module, &r.Mode, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan detector config: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *ControlStore) UpsertDetectorConfig(ctx context.Context, cfg control.DetectorConfigRecord) error {
	if cfg.UpdatedAt.IsZero() {
		cfg.UpdatedAt = time.Now().UTC()
	}
	query := `INSERT INTO raiwall_detector_config (module, mode, updated_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT (module) DO UPDATE SET mode = EXCLUDED.mode, updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query, cfg.Module, cfg.Mode, cfg.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert detector config: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteDetectorConfig(ctx context.Context, module string) error {
	query := `DELETE FROM raiwall_detector_config WHERE module = $1`
	_, err := s.db.ExecContext(ctx, query, module)
	if err != nil {
		return fmt.Errorf("delete detector config: %w", err)
	}
	return nil
}

// Per-Application Semantic Policy Overrides

func (s *ControlStore) ListAppSemanticPolicies(ctx context.Context) ([]control.AppSemanticPolicyRecord, error) {
	query := `SELECT app_id, policy, updated_at FROM raiwall_app_semantic_policies ORDER BY app_id ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list app semantic policies: %w", err)
	}
	defer rows.Close()

	var result []control.AppSemanticPolicyRecord
	for rows.Next() {
		var r control.AppSemanticPolicyRecord
		if err := rows.Scan(&r.AppID, &r.Policy, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan app semantic policy: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *ControlStore) UpsertAppSemanticPolicy(ctx context.Context, rec control.AppSemanticPolicyRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	query := `INSERT INTO raiwall_app_semantic_policies (app_id, policy, updated_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT (app_id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query, rec.AppID, rec.Policy, rec.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert app semantic policy: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteAppSemanticPolicy(ctx context.Context, appID string) error {
	query := `DELETE FROM raiwall_app_semantic_policies WHERE app_id = $1`
	_, err := s.db.ExecContext(ctx, query, appID)
	if err != nil {
		return fmt.Errorf("delete app semantic policy: %w", err)
	}
	return nil
}
