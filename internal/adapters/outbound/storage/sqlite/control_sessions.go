package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// CreateAdminSession stores a new opaque operator session.
func (s *Store) CreateAdminSession(ctx context.Context, session control.AdminSession) error {
	_, err := s.conn().ExecContext(ctx, `
		INSERT INTO raiwall_sessions
			(id, user_id, token_hash, created_at, last_seen_at, idle_expires_at,
			 absolute_expires_at, client_ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.TokenHash, session.CreatedAt, session.LastSeenAt,
		session.IdleExpiresAt, session.AbsoluteExpiresAt, session.ClientIP, session.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

// GetAdminSessionByTokenHash resolves a session by its hashed bearer token.
func (s *Store) GetAdminSessionByTokenHash(ctx context.Context, tokenHash string) (control.AdminSession, error) {
	var session control.AdminSession
	var revoked sql.NullTime
	err := s.conn().QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at,
		       absolute_expires_at, revoked_at, client_ip, user_agent
		FROM raiwall_sessions WHERE token_hash = ? LIMIT 1`, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.CreatedAt, &session.LastSeenAt,
		&session.IdleExpiresAt, &session.AbsoluteExpiresAt, &revoked,
		&session.ClientIP, &session.UserAgent,
	)
	if err != nil {
		return control.AdminSession{}, err
	}
	session.RevokedAt = revoked
	return session, nil
}

// TouchAdminSession records activity and extends the idle deadline.
func (s *Store) TouchAdminSession(ctx context.Context, id string, seenAt, idleExpiresAt time.Time) error {
	_, err := s.conn().ExecContext(ctx,
		`UPDATE raiwall_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?`,
		seenAt, idleExpiresAt, id)
	return err
}

// RevokeAdminSession marks one session revoked.
func (s *Store) RevokeAdminSession(ctx context.Context, id string, revokedAt time.Time) error {
	_, err := s.conn().ExecContext(ctx,
		`UPDATE raiwall_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		revokedAt, id)
	return err
}

// RevokeAdminSessionsForUser revokes every active session for a user.
func (s *Store) RevokeAdminSessionsForUser(ctx context.Context, userID string, revokedAt time.Time) error {
	_, err := s.conn().ExecContext(ctx,
		`UPDATE raiwall_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		revokedAt, userID)
	return err
}

// DeleteExpiredAdminSessions removes sessions past their absolute deadline or
// already revoked. It returns the number of removed rows.
func (s *Store) DeleteExpiredAdminSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.conn().ExecContext(ctx,
		`DELETE FROM raiwall_sessions WHERE absolute_expires_at < ? OR revoked_at IS NOT NULL`, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
