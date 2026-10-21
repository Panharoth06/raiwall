package sqlite

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Snapshots

func (s *Store) CreateSnapshot(ctx context.Context, snap control.ConfigSnapshotRecord) (control.ConfigSnapshotRecord, error) {
	r, err := s.Queries.CreateSnapshot(ctx, CreateSnapshotParams{
		SnapshotData: snap.SnapshotData,
		Author:       snap.Author,
		Description:  snap.Description,
		CreatedAt:    snap.CreatedAt,
	})
	if err != nil {
		return control.ConfigSnapshotRecord{}, err
	}
	return control.ConfigSnapshotRecord{
		Version:      r.Version,
		SnapshotData: r.SnapshotData,
		Author:       r.Author,
		Description:  r.Description,
		CreatedAt:    r.CreatedAt,
	}, nil
}

func (s *Store) GetSnapshotByVersion(ctx context.Context, version int64) (control.ConfigSnapshotRecord, error) {
	r, err := s.Queries.GetSnapshotByVersion(ctx, version)
	if err != nil {
		return control.ConfigSnapshotRecord{}, err
	}
	return toControlSnapshotRecord(r), nil
}

func (s *Store) GetLatestSnapshot(ctx context.Context) (control.ConfigSnapshotRecord, error) {
	r, err := s.Queries.GetLatestSnapshot(ctx)
	if err != nil {
		return control.ConfigSnapshotRecord{}, err
	}
	return toControlSnapshotRecord(r), nil
}

func (s *Store) ListSnapshots(ctx context.Context) ([]control.ConfigSnapshotRecord, error) {
	rows, err := s.Queries.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ConfigSnapshotRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlSnapshotRecord(r)
	}
	return res, nil
}

// Users

func (s *Store) ListUsers(ctx context.Context) ([]control.UserRecord, error) {
	rows, err := s.Queries.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.UserRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlUserRecord(r)
	}
	return res, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (control.UserRecord, error) {
	r, err := s.Queries.GetUserByID(ctx, id)
	if err != nil {
		return control.UserRecord{}, err
	}
	return toControlUserRecord(r), nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (control.UserRecord, error) {
	r, err := s.Queries.GetUserByUsername(ctx, username)
	if err != nil {
		return control.UserRecord{}, err
	}
	return toControlUserRecord(r), nil
}

func (s *Store) CreateUser(ctx context.Context, user control.UserRecord) error {
	return s.Queries.CreateUser(ctx, CreateUserParams{
		ID:           user.ID,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		Role:         user.Role,
		IsActive:     user.IsActive,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	})
}

func (s *Store) UpdateUser(ctx context.Context, user control.UserRecord) error {
	return s.Queries.UpdateUser(ctx, UpdateUserParams{
		ID:           user.ID,
		PasswordHash: user.PasswordHash,
		Role:         user.Role,
		IsActive:     user.IsActive,
		UpdatedAt:    user.UpdatedAt,
	})
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.Queries.DeleteUser(ctx, id)
}

// API Keys

func (s *Store) ListAPIKeys(ctx context.Context) ([]control.ApiKeyRecord, error) {
	rows, err := s.Queries.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ApiKeyRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlApiKeyRecord(r)
	}
	return res, nil
}

func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (control.ApiKeyRecord, error) {
	r, err := s.Queries.GetAPIKeyByID(ctx, id)
	if err != nil {
		return control.ApiKeyRecord{}, err
	}
	return toControlApiKeyRecord(r), nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, keyHash string) (control.ApiKeyRecord, error) {
	r, err := s.Queries.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return control.ApiKeyRecord{}, err
	}
	return toControlApiKeyRecord(r), nil
}

func (s *Store) CreateAPIKey(ctx context.Context, key control.ApiKeyRecord) error {
	return s.Queries.CreateAPIKey(ctx, CreateAPIKeyParams{
		ID:         key.ID,
		Name:       key.Name,
		KeyHash:    key.KeyHash,
		Role:       key.Role,
		ExpiresAt:  key.ExpiresAt,
		IsActive:   key.IsActive,
		CreatedAt:  key.CreatedAt,
		LastUsedAt: key.LastUsedAt,
	})
}

func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, id string, lastUsedAt time.Time) error {
	return s.Queries.UpdateAPIKeyLastUsed(ctx, UpdateAPIKeyLastUsedParams{
		ID:         id,
		LastUsedAt: toNullTime(lastUsedAt),
	})
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	return s.Queries.DeleteAPIKey(ctx, id)
}

// Forwarding Rules

func (s *Store) ListForwardingRules(ctx context.Context) ([]control.ForwardingRuleRecord, error) {
	rows, err := s.Queries.ListForwardingRules(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ForwardingRuleRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlForwardingRule(r)
	}
	return res, nil
}

func (s *Store) ListForwardingRulesByApp(ctx context.Context, appID string) ([]control.ForwardingRuleRecord, error) {
	rows, err := s.Queries.ListForwardingRulesByApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	res := make([]control.ForwardingRuleRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlForwardingRule(r)
	}
	return res, nil
}

func (s *Store) ListActiveForwardingRulesByApp(ctx context.Context, appID string) ([]control.ForwardingRuleRecord, error) {
	rows, err := s.Queries.ListActiveForwardingRulesByApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	res := make([]control.ForwardingRuleRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlForwardingRule(r)
	}
	return res, nil
}

func (s *Store) ListAllActiveForwardingRules(ctx context.Context) ([]control.ForwardingRuleRecord, error) {
	rows, err := s.Queries.ListAllActiveForwardingRules(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.ForwardingRuleRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlForwardingRule(r)
	}
	return res, nil
}

func (s *Store) GetForwardingRule(ctx context.Context, id string) (control.ForwardingRuleRecord, error) {
	r, err := s.Queries.GetForwardingRule(ctx, id)
	if err != nil {
		return control.ForwardingRuleRecord{}, err
	}
	return toControlForwardingRule(r), nil
}

func (s *Store) CreateForwardingRule(ctx context.Context, rule control.ForwardingRuleRecord) error {
	return s.Queries.CreateForwardingRule(ctx, CreateForwardingRuleParams{
		ID:                 rule.ID,
		AppID:              rule.AppID,
		Prefix:             rule.Prefix,
		Upstreams:          rule.Upstreams,
		StripPrefix:        rule.StripPrefix,
		HostHeaderOverride: rule.HostHeaderOverride,
		Comment:            rule.Comment,
		IsActive:           rule.IsActive,
		CreatedAt:          rule.CreatedAt,
		UpdatedAt:          rule.UpdatedAt,
	})
}

func (s *Store) UpdateForwardingRule(ctx context.Context, rule control.ForwardingRuleRecord) error {
	return s.Queries.UpdateForwardingRule(ctx, UpdateForwardingRuleParams{
		ID:                 rule.ID,
		Prefix:             rule.Prefix,
		Upstreams:          rule.Upstreams,
		StripPrefix:        rule.StripPrefix,
		HostHeaderOverride: rule.HostHeaderOverride,
		Comment:            rule.Comment,
		IsActive:           rule.IsActive,
		UpdatedAt:          rule.UpdatedAt,
	})
}

func (s *Store) DeleteForwardingRule(ctx context.Context, id string) error {
	return s.Queries.DeleteForwardingRule(ctx, id)
}

func (s *Store) DeleteForwardingRulesByApp(ctx context.Context, appID string) error {
	return s.Queries.DeleteForwardingRulesByApp(ctx, appID)
}

// API Resources

func (s *Store) ListAPIResourcesByApp(ctx context.Context, appID string) ([]control.ApiResourceRecord, error) {
	rows, err := s.Queries.ListAPIResourcesByApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	res := make([]control.ApiResourceRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlApiResource(r)
	}
	return res, nil
}

func (s *Store) GetAPIResource(ctx context.Context, id string) (control.ApiResourceRecord, error) {
	r, err := s.Queries.GetAPIResource(ctx, id)
	if err != nil {
		return control.ApiResourceRecord{}, err
	}
	return toControlApiResource(r), nil
}

func (s *Store) UpsertAPIResource(ctx context.Context, res control.ApiResourceRecord) error {
	return s.Queries.UpsertAPIResource(ctx, UpsertAPIResourceParams{
		ID:          res.ID,
		AppID:       res.AppID,
		Method:      res.Method,
		PathPattern: res.PathPattern,
		ContentType: res.ContentType,
		HitCount:    res.HitCount,
		LastSeen:    res.LastSeen,
		CreatedAt:   res.CreatedAt,
	})
}

func (s *Store) DeleteAPIResource(ctx context.Context, id string) error {
	return s.Queries.DeleteAPIResource(ctx, id)
}

func (s *Store) DeleteAPIResourcesByApp(ctx context.Context, appID string) error {
	return s.Queries.DeleteAPIResourcesByApp(ctx, appID)
}
