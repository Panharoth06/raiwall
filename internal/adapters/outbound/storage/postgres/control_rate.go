package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Rate Policies

func (s *ControlStore) ListRatePolicies(ctx context.Context) ([]control.RatePolicy, error) {
	query := `SELECT id, name, host, tier1_rate, tier1_burst, tier1_period_sec,
	                 tier2_threshold, tier2_period_sec, tier2_ban_duration_sec,
	                 tier3_threshold, tier3_ban_duration_sec, waiting_room_enabled,
	                 waiting_room_capacity, waiting_room_paths, is_active, created_at, updated_at
	          FROM raiwall_rate_policies ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list rate policies: %w", err)
	}
	defer rows.Close()

	var list []control.RatePolicy
	for rows.Next() {
		var rp control.RatePolicy
		err := rows.Scan(
			&rp.ID, &rp.Name, &rp.Host, &rp.Tier1Rate, &rp.Tier1Burst, &rp.Tier1PeriodSec,
			&rp.Tier2Threshold, &rp.Tier2PeriodSec, &rp.Tier2BanDurationSec,
			&rp.Tier3Threshold, &rp.Tier3BanDurationSec, &rp.WaitingRoomEnabled,
			&rp.WaitingRoomCapacity, &rp.WaitingRoomPaths, &rp.IsActive,
			&rp.CreatedAt, &rp.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan rate policy: %w", err)
		}
		list = append(list, rp)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListActiveRatePolicies(ctx context.Context) ([]control.RatePolicy, error) {
	query := `SELECT id, name, host, tier1_rate, tier1_burst, tier1_period_sec,
	                 tier2_threshold, tier2_period_sec, tier2_ban_duration_sec,
	                 tier3_threshold, tier3_ban_duration_sec, waiting_room_enabled,
	                 waiting_room_capacity, waiting_room_paths, is_active, created_at, updated_at
	          FROM raiwall_rate_policies WHERE is_active = 1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active rate policies: %w", err)
	}
	defer rows.Close()

	var list []control.RatePolicy
	for rows.Next() {
		var rp control.RatePolicy
		err := rows.Scan(
			&rp.ID, &rp.Name, &rp.Host, &rp.Tier1Rate, &rp.Tier1Burst, &rp.Tier1PeriodSec,
			&rp.Tier2Threshold, &rp.Tier2PeriodSec, &rp.Tier2BanDurationSec,
			&rp.Tier3Threshold, &rp.Tier3BanDurationSec, &rp.WaitingRoomEnabled,
			&rp.WaitingRoomCapacity, &rp.WaitingRoomPaths, &rp.IsActive,
			&rp.CreatedAt, &rp.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan active rate policy: %w", err)
		}
		list = append(list, rp)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetRatePolicy(ctx context.Context, id string) (control.RatePolicy, error) {
	query := `SELECT id, name, host, tier1_rate, tier1_burst, tier1_period_sec,
	                 tier2_threshold, tier2_period_sec, tier2_ban_duration_sec,
	                 tier3_threshold, tier3_ban_duration_sec, waiting_room_enabled,
	                 waiting_room_capacity, waiting_room_paths, is_active, created_at, updated_at
	          FROM raiwall_rate_policies WHERE id = $1 LIMIT 1`
	var rp control.RatePolicy
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&rp.ID, &rp.Name, &rp.Host, &rp.Tier1Rate, &rp.Tier1Burst, &rp.Tier1PeriodSec,
		&rp.Tier2Threshold, &rp.Tier2PeriodSec, &rp.Tier2BanDurationSec,
		&rp.Tier3Threshold, &rp.Tier3BanDurationSec, &rp.WaitingRoomEnabled,
		&rp.WaitingRoomCapacity, &rp.WaitingRoomPaths, &rp.IsActive,
		&rp.CreatedAt, &rp.UpdatedAt,
	)
	if err != nil {
		return control.RatePolicy{}, fmt.Errorf("get rate policy %s: %w", id, err)
	}
	return rp, nil
}

func (s *ControlStore) CreateRatePolicy(ctx context.Context, policy control.RatePolicy) error {
	query := `INSERT INTO raiwall_rate_policies (
		id, name, host, tier1_rate, tier1_burst, tier1_period_sec,
		tier2_threshold, tier2_period_sec, tier2_ban_duration_sec,
		tier3_threshold, tier3_ban_duration_sec, waiting_room_enabled,
		waiting_room_capacity, waiting_room_paths, is_active, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`
	_, err := s.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Host, policy.Tier1Rate, policy.Tier1Burst, policy.Tier1PeriodSec,
		policy.Tier2Threshold, policy.Tier2PeriodSec, policy.Tier2BanDurationSec,
		policy.Tier3Threshold, policy.Tier3BanDurationSec, policy.WaitingRoomEnabled,
		policy.WaitingRoomCapacity, policy.WaitingRoomPaths, policy.IsActive,
		policy.CreatedAt, policy.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateRatePolicy(ctx context.Context, policy control.RatePolicy) error {
	query := `UPDATE raiwall_rate_policies SET
		name = $1, host = $2, tier1_rate = $3, tier1_burst = $4, tier1_period_sec = $5,
		tier2_threshold = $6, tier2_period_sec = $7, tier2_ban_duration_sec = $8,
		tier3_threshold = $9, tier3_ban_duration_sec = $10, waiting_room_enabled = $11,
		waiting_room_capacity = $12, waiting_room_paths = $13, is_active = $14, updated_at = $15
	WHERE id = $16`
	_, err := s.db.ExecContext(ctx, query,
		policy.Name, policy.Host, policy.Tier1Rate, policy.Tier1Burst, policy.Tier1PeriodSec,
		policy.Tier2Threshold, policy.Tier2PeriodSec, policy.Tier2BanDurationSec,
		policy.Tier3Threshold, policy.Tier3BanDurationSec, policy.WaitingRoomEnabled,
		policy.WaitingRoomCapacity, policy.WaitingRoomPaths, policy.IsActive,
		policy.UpdatedAt, policy.ID,
	)
	return err
}

func (s *ControlStore) DeleteRatePolicy(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_rate_policies WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
