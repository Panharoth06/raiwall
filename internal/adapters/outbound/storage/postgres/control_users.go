package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Users

func (s *ControlStore) ListUsers(ctx context.Context) ([]control.UserRecord, error) {
	query := `SELECT id, username, password_hash, role, is_active, created_at, updated_at
	          FROM raiwall_users ORDER BY username ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var list []control.UserRecord
	for rows.Next() {
		var u control.UserRecord
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (s *ControlStore) GetUserByID(ctx context.Context, id string) (control.UserRecord, error) {
	query := `SELECT id, username, password_hash, role, is_active, created_at, updated_at
	          FROM raiwall_users WHERE id = $1 LIMIT 1`
	var u control.UserRecord
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return control.UserRecord{}, fmt.Errorf("get user %s: %w", id, err)
	}
	return u, nil
}

func (s *ControlStore) GetUserByUsername(ctx context.Context, username string) (control.UserRecord, error) {
	query := `SELECT id, username, password_hash, role, is_active, created_at, updated_at
	          FROM raiwall_users WHERE username = $1 LIMIT 1`
	var u control.UserRecord
	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return control.UserRecord{}, fmt.Errorf("get user %s: %w", username, err)
	}
	return u, nil
}

func (s *ControlStore) CreateUser(ctx context.Context, user control.UserRecord) error {
	query := `INSERT INTO raiwall_users (id, username, password_hash, role, is_active, created_at, updated_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.db.ExecContext(ctx, query,
		user.ID, user.Username, user.PasswordHash, user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateUser(ctx context.Context, user control.UserRecord) error {
	query := `UPDATE raiwall_users SET
		password_hash = $1, role = $2, is_active = $3, updated_at = $4
	WHERE id = $5`
	_, err := s.db.ExecContext(ctx, query,
		user.PasswordHash, user.Role, user.IsActive, user.UpdatedAt, user.ID,
	)
	return err
}

func (s *ControlStore) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM raiwall_users WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
