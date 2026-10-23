package sqlite

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Identity user directory (end-user accounts, separate from admin operators).

func (s *Store) ListIdentityUsers(ctx context.Context) ([]control.IdentityUserRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, password_hash, email, display_name, totp_secret, totp_enabled, app_ids, enabled, created_at, updated_at FROM raiwall_identity_users ORDER BY username ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.IdentityUserRecord
	for rows.Next() {
		var u control.IdentityUserRecord
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.DisplayName,
			&u.TOTPSecret, &u.TOTPEnabled, &u.AppIDs, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (s *Store) GetIdentityUserByID(ctx context.Context, id string) (control.IdentityUserRecord, error) {
	var u control.IdentityUserRecord
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, email, display_name, totp_secret, totp_enabled, app_ids, enabled, created_at, updated_at FROM raiwall_identity_users WHERE id = ?",
		id).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.DisplayName,
		&u.TOTPSecret, &u.TOTPEnabled, &u.AppIDs, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (s *Store) GetIdentityUserByUsername(ctx context.Context, username string) (control.IdentityUserRecord, error) {
	var u control.IdentityUserRecord
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, email, display_name, totp_secret, totp_enabled, app_ids, enabled, created_at, updated_at FROM raiwall_identity_users WHERE username = ?",
		username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &u.DisplayName,
		&u.TOTPSecret, &u.TOTPEnabled, &u.AppIDs, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (s *Store) UpsertIdentityUser(ctx context.Context, user control.IdentityUserRecord) error {
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = user.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_identity_users (id, username, password_hash, email, display_name, totp_secret, totp_enabled, app_ids, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, user.PasswordHash, user.Email, user.DisplayName,
		user.TOTPSecret, user.TOTPEnabled, user.AppIDs, user.Enabled, user.CreatedAt, user.UpdatedAt)
	return err
}

func (s *Store) DeleteIdentityUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_identity_users WHERE id = ?", id)
	return err
}

// Identity provider connectors (external IdPs).

func (s *Store) ListIdentityProviders(ctx context.Context) ([]control.IdentityProviderRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, type, name, config, enabled, created_at, updated_at FROM raiwall_identity_providers ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.IdentityProviderRecord
	for rows.Next() {
		var p control.IdentityProviderRecord
		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Config, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *Store) UpsertIdentityProvider(ctx context.Context, provider control.IdentityProviderRecord) error {
	if provider.UpdatedAt.IsZero() {
		provider.UpdatedAt = time.Now().UTC()
	}
	if provider.CreatedAt.IsZero() {
		provider.CreatedAt = provider.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO raiwall_identity_providers (id, type, name, config, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		provider.ID, provider.Type, provider.Name, provider.Config, provider.Enabled, provider.CreatedAt, provider.UpdatedAt)
	return err
}

func (s *Store) DeleteIdentityProvider(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_identity_providers WHERE id = ?", id)
	return err
}
