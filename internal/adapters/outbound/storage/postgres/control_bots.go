package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Bot Configs

func (s *ControlStore) ListBotConfigs(ctx context.Context) ([]control.BotConfig, error) {
	query := `SELECT id, host, pow_enabled, pow_difficulty, trap_urls, is_active, created_at, updated_at
	          FROM raiwall_bot_configs ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list bot configs: %w", err)
	}
	defer rows.Close()

	var list []control.BotConfig
	for rows.Next() {
		var bc control.BotConfig
		err := rows.Scan(
			&bc.ID, &bc.Host, &bc.PowEnabled, &bc.PowDifficulty,
			&bc.TrapUrls, &bc.IsActive, &bc.CreatedAt, &bc.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan bot config: %w", err)
		}
		list = append(list, bc)
	}
	return list, rows.Err()
}

func (s *ControlStore) ListActiveBotConfigs(ctx context.Context) ([]control.BotConfig, error) {
	query := `SELECT id, host, pow_enabled, pow_difficulty, trap_urls, is_active, created_at, updated_at
	          FROM raiwall_bot_configs WHERE is_active = 1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list active bot configs: %w", err)
	}
	defer rows.Close()

	var list []control.BotConfig
	for rows.Next() {
		var bc control.BotConfig
		err := rows.Scan(
			&bc.ID, &bc.Host, &bc.PowEnabled, &bc.PowDifficulty,
			&bc.TrapUrls, &bc.IsActive, &bc.CreatedAt, &bc.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan active bot config: %w", err)
		}
		list = append(list, bc)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetBotConfig(ctx context.Context, id string) (control.BotConfig, error) {
	query := `SELECT id, host, pow_enabled, pow_difficulty, trap_urls, is_active, created_at, updated_at
	          FROM raiwall_bot_configs WHERE id = $1 LIMIT 1`
	var bc control.BotConfig
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&bc.ID, &bc.Host, &bc.PowEnabled, &bc.PowDifficulty,
		&bc.TrapUrls, &bc.IsActive, &bc.CreatedAt, &bc.UpdatedAt,
	)
	if err != nil {
		return control.BotConfig{}, fmt.Errorf("get bot config %s: %w", id, err)
	}
	return bc, nil
}

func (s *ControlStore) CreateBotConfig(ctx context.Context, cfg control.BotConfig) error {
	query := `INSERT INTO raiwall_bot_configs (
		id, host, pow_enabled, pow_difficulty, trap_urls, is_active, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.db.ExecContext(ctx, query,
		cfg.ID, cfg.Host, cfg.PowEnabled, cfg.PowDifficulty,
		cfg.TrapUrls, cfg.IsActive, cfg.CreatedAt, cfg.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateBotConfig(ctx context.Context, cfg control.BotConfig) error {
	query := `UPDATE raiwall_bot_configs SET
		host = $1, pow_enabled = $2, pow_difficulty = $3, trap_urls = $4,
		is_active = $5, updated_at = $6
	WHERE id = $7`
	_, err := s.db.ExecContext(ctx, query,
		cfg.Host, cfg.PowEnabled, cfg.PowDifficulty, cfg.TrapUrls,
		cfg.IsActive, cfg.UpdatedAt, cfg.ID,
	)
	return err
}

func (s *ControlStore) DeleteBotConfig(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_bot_configs WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
