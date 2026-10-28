package sqlite

import (
	"context"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// ACL Rules

func (s *Store) ListACLRules(ctx context.Context) ([]control.AclRule, error) {
	rows, err := s.Queries.ListACLRules(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.AclRule, len(rows))
	for i, r := range rows {
		res[i] = toControlAclRule(r)
	}
	return res, nil
}

func (s *Store) ListActiveACLRules(ctx context.Context) ([]control.AclRule, error) {
	rows, err := s.Queries.ListActiveACLRules(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.AclRule, len(rows))
	for i, r := range rows {
		res[i] = toControlAclRule(r)
	}
	return res, nil
}

func (s *Store) GetACLRule(ctx context.Context, id string) (control.AclRule, error) {
	r, err := s.Queries.GetACLRule(ctx, id)
	if err != nil {
		return control.AclRule{}, err
	}
	return toControlAclRule(r), nil
}

func (s *Store) CreateACLRule(ctx context.Context, rule control.AclRule) error {
	return s.Queries.CreateACLRule(ctx, CreateACLRuleParams{
		ID:                 rule.ID,
		Name:               rule.Name,
		Expression:         rule.Expression,
		Action:             rule.Action,
		Priority:           rule.Priority,
		StatusCode:         rule.StatusCode,
		RedirectUrl:        rule.RedirectUrl,
		IsActive:           rule.IsActive,
		ContinueInspection: rule.ContinueInspection,
		CreatedAt:          rule.CreatedAt,
		UpdatedAt:          rule.UpdatedAt,
	})
}

func (s *Store) UpdateACLRule(ctx context.Context, rule control.AclRule) error {
	return s.Queries.UpdateACLRule(ctx, UpdateACLRuleParams{
		ID:                 rule.ID,
		Name:               rule.Name,
		Expression:         rule.Expression,
		Action:             rule.Action,
		Priority:           rule.Priority,
		StatusCode:         rule.StatusCode,
		RedirectUrl:        rule.RedirectUrl,
		IsActive:           rule.IsActive,
		ContinueInspection: rule.ContinueInspection,
		UpdatedAt:          rule.UpdatedAt,
	})
}

func (s *Store) DeleteACLRule(ctx context.Context, id string) error {
	return s.Queries.DeleteACLRule(ctx, id)
}

// Rate Policies

func (s *Store) ListRatePolicies(ctx context.Context) ([]control.RatePolicy, error) {
	rows, err := s.Queries.ListRatePolicies(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.RatePolicy, len(rows))
	for i, r := range rows {
		res[i] = toControlRatePolicy(r)
	}
	return res, nil
}

func (s *Store) ListActiveRatePolicies(ctx context.Context) ([]control.RatePolicy, error) {
	rows, err := s.Queries.ListActiveRatePolicies(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.RatePolicy, len(rows))
	for i, r := range rows {
		res[i] = toControlRatePolicy(r)
	}
	return res, nil
}

func (s *Store) GetRatePolicy(ctx context.Context, id string) (control.RatePolicy, error) {
	r, err := s.Queries.GetRatePolicy(ctx, id)
	if err != nil {
		return control.RatePolicy{}, err
	}
	return toControlRatePolicy(r), nil
}

func (s *Store) CreateRatePolicy(ctx context.Context, policy control.RatePolicy) error {
	return s.Queries.CreateRatePolicy(ctx, CreateRatePolicyParams{
		ID:                  policy.ID,
		Name:                policy.Name,
		Host:                policy.Host,
		Tier1Rate:           policy.Tier1Rate,
		Tier1Burst:          policy.Tier1Burst,
		Tier1PeriodSec:      policy.Tier1PeriodSec,
		Tier2Threshold:      policy.Tier2Threshold,
		Tier2PeriodSec:      policy.Tier2PeriodSec,
		Tier2BanDurationSec: policy.Tier2BanDurationSec,
		Tier3Threshold:      policy.Tier3Threshold,
		Tier3BanDurationSec: policy.Tier3BanDurationSec,
		WaitingRoomEnabled:  policy.WaitingRoomEnabled,
		WaitingRoomCapacity: policy.WaitingRoomCapacity,
		WaitingRoomPaths:    policy.WaitingRoomPaths,
		IsActive:            policy.IsActive,
		CreatedAt:           policy.CreatedAt,
		UpdatedAt:           policy.UpdatedAt,
	})
}

func (s *Store) UpdateRatePolicy(ctx context.Context, policy control.RatePolicy) error {
	return s.Queries.UpdateRatePolicy(ctx, UpdateRatePolicyParams{
		ID:                  policy.ID,
		Name:                policy.Name,
		Host:                policy.Host,
		Tier1Rate:           policy.Tier1Rate,
		Tier1Burst:          policy.Tier1Burst,
		Tier1PeriodSec:      policy.Tier1PeriodSec,
		Tier2Threshold:      policy.Tier2Threshold,
		Tier2PeriodSec:      policy.Tier2PeriodSec,
		Tier2BanDurationSec: policy.Tier2BanDurationSec,
		Tier3Threshold:      policy.Tier3Threshold,
		Tier3BanDurationSec: policy.Tier3BanDurationSec,
		WaitingRoomEnabled:  policy.WaitingRoomEnabled,
		WaitingRoomCapacity: policy.WaitingRoomCapacity,
		WaitingRoomPaths:    policy.WaitingRoomPaths,
		IsActive:            policy.IsActive,
		UpdatedAt:           policy.UpdatedAt,
	})
}

func (s *Store) DeleteRatePolicy(ctx context.Context, id string) error {
	return s.Queries.DeleteRatePolicy(ctx, id)
}

// Bot Configs

func (s *Store) ListBotConfigs(ctx context.Context) ([]control.BotConfig, error) {
	rows, err := s.Queries.ListBotConfigs(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.BotConfig, len(rows))
	for i, r := range rows {
		res[i] = toControlBotConfig(r)
	}
	return res, nil
}

func (s *Store) ListActiveBotConfigs(ctx context.Context) ([]control.BotConfig, error) {
	rows, err := s.Queries.ListActiveBotConfigs(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.BotConfig, len(rows))
	for i, r := range rows {
		res[i] = toControlBotConfig(r)
	}
	return res, nil
}

func (s *Store) GetBotConfig(ctx context.Context, id string) (control.BotConfig, error) {
	r, err := s.Queries.GetBotConfig(ctx, id)
	if err != nil {
		return control.BotConfig{}, err
	}
	return toControlBotConfig(r), nil
}

func (s *Store) CreateBotConfig(ctx context.Context, cfg control.BotConfig) error {
	return s.Queries.CreateBotConfig(ctx, CreateBotConfigParams{
		ID:            cfg.ID,
		Host:          cfg.Host,
		PowEnabled:    cfg.PowEnabled,
		PowDifficulty: cfg.PowDifficulty,
		TrapUrls:      cfg.TrapUrls,
		IsActive:      cfg.IsActive,
		CreatedAt:     cfg.CreatedAt,
		UpdatedAt:     cfg.UpdatedAt,
	})
}

func (s *Store) UpdateBotConfig(ctx context.Context, cfg control.BotConfig) error {
	return s.Queries.UpdateBotConfig(ctx, UpdateBotConfigParams{
		ID:            cfg.ID,
		Host:          cfg.Host,
		PowEnabled:    cfg.PowEnabled,
		PowDifficulty: cfg.PowDifficulty,
		TrapUrls:      cfg.TrapUrls,
		IsActive:      cfg.IsActive,
		UpdatedAt:     cfg.UpdatedAt,
	})
}

func (s *Store) DeleteBotConfig(ctx context.Context, id string) error {
	return s.Queries.DeleteBotConfig(ctx, id)
}
