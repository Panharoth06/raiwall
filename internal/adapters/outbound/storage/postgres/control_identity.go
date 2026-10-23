package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Identity user directory (end-user accounts, separate from admin operators).

const identityUserColumns = `id, username, password_hash, email, display_name, totp_secret, totp_enabled, app_ids, enabled, created_at, updated_at`

func scanIdentityUser(scanner interface{ Scan(...any) error }) (control.IdentityUserRecord, error) {
	var u control.IdentityUserRecord
	err := scanner.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.DisplayName,
		&u.TOTPSecret, &u.TOTPEnabled, &u.AppIDs, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (s *ControlStore) ListIdentityUsers(ctx context.Context) ([]control.IdentityUserRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+identityUserColumns+" FROM raiwall_identity_users ORDER BY username ASC")
	if err != nil {
		return nil, fmt.Errorf("list identity users: %w", err)
	}
	defer rows.Close()

	var result []control.IdentityUserRecord
	for rows.Next() {
		u, err := scanIdentityUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan identity user: %w", err)
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetIdentityUserByID(ctx context.Context, id string) (control.IdentityUserRecord, error) {
	u, err := scanIdentityUser(s.db.QueryRowContext(ctx,
		"SELECT "+identityUserColumns+" FROM raiwall_identity_users WHERE id = $1", id))
	if err != nil {
		return u, fmt.Errorf("get identity user by id: %w", err)
	}
	return u, nil
}

func (s *ControlStore) GetIdentityUserByUsername(ctx context.Context, username string) (control.IdentityUserRecord, error) {
	u, err := scanIdentityUser(s.db.QueryRowContext(ctx,
		"SELECT "+identityUserColumns+" FROM raiwall_identity_users WHERE username = $1", username))
	if err != nil {
		return u, fmt.Errorf("get identity user by username: %w", err)
	}
	return u, nil
}

func (s *ControlStore) UpsertIdentityUser(ctx context.Context, user control.IdentityUserRecord) error {
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = user.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_identity_users (`+identityUserColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO UPDATE SET username=EXCLUDED.username, password_hash=EXCLUDED.password_hash,
		email=EXCLUDED.email, display_name=EXCLUDED.display_name, totp_secret=EXCLUDED.totp_secret,
		totp_enabled=EXCLUDED.totp_enabled, app_ids=EXCLUDED.app_ids, enabled=EXCLUDED.enabled,
		updated_at=EXCLUDED.updated_at`,
		user.ID, user.Username, user.PasswordHash, user.Email, user.DisplayName,
		user.TOTPSecret, user.TOTPEnabled, user.AppIDs, user.Enabled, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert identity user: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteIdentityUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_identity_users WHERE id = $1", id); err != nil {
		return fmt.Errorf("delete identity user: %w", err)
	}
	return nil
}

// Identity provider connectors (external IdPs).

func (s *ControlStore) ListIdentityProviders(ctx context.Context) ([]control.IdentityProviderRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, type, name, config, enabled, created_at, updated_at FROM raiwall_identity_providers ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("list identity providers: %w", err)
	}
	defer rows.Close()

	var result []control.IdentityProviderRecord
	for rows.Next() {
		var p control.IdentityProviderRecord
		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Config, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan identity provider: %w", err)
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *ControlStore) UpsertIdentityProvider(ctx context.Context, provider control.IdentityProviderRecord) error {
	if provider.UpdatedAt.IsZero() {
		provider.UpdatedAt = time.Now().UTC()
	}
	if provider.CreatedAt.IsZero() {
		provider.CreatedAt = provider.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_identity_providers (id, type, name, config, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET type=EXCLUDED.type, name=EXCLUDED.name, config=EXCLUDED.config,
		enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at`,
		provider.ID, provider.Type, provider.Name, provider.Config, provider.Enabled, provider.CreatedAt, provider.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert identity provider: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteIdentityProvider(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_identity_providers WHERE id = $1", id); err != nil {
		return fmt.Errorf("delete identity provider: %w", err)
	}
	return nil
}
