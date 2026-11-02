package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

const auditColumns = `id, occurred_at, actor_type, actor_id, actor_name, role, action,
	target_type, target_id, method, path, status_code, request_id, client_ip,
	user_agent, snapshot_version, detail`

func scanAuditEvent(scanner interface{ Scan(...any) error }) (control.AuditEvent, error) {
	var event control.AuditEvent
	err := scanner.Scan(
		&event.ID, &event.OccurredAt, &event.ActorType, &event.ActorID, &event.ActorName,
		&event.Role, &event.Action, &event.TargetType, &event.TargetID, &event.Method,
		&event.Path, &event.StatusCode, &event.RequestID, &event.ClientIP, &event.UserAgent,
		&event.SnapshotVersion, &event.Detail,
	)
	return event, err
}

// CreateAuditEvent appends one audit record and links it into the hash chain.
// The event, its chain row and the head update commit atomically. Inside
// WithTx the caller's transaction is used; otherwise a private one is opened
// (never through the pool while a transaction is open, since the pool has a
// single connection).
func (s *Store) CreateAuditEvent(ctx context.Context, event control.AuditEvent) error {
	if s.tx != nil {
		return s.appendAudit(ctx, s.tx, event)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create audit event: begin: %w", err)
	}
	if err := s.appendAudit(ctx, tx, event); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create audit event: commit: %w", err)
	}
	return nil
}

func (s *Store) appendAudit(ctx context.Context, q DBTX, event control.AuditEvent) error {
	event.OccurredAt = event.OccurredAt.UTC().Truncate(control.AuditTimePrecision)

	// Taking the write lock first keeps concurrent writers from both reading
	// the same chain head.
	if _, err := q.ExecContext(ctx, `UPDATE raiwall_admin_audit_head SET seq = seq WHERE id = 1`); err != nil {
		return fmt.Errorf("create audit event: lock chain head: %w", err)
	}
	var headSeq int64
	var headHash string
	if err := q.QueryRowContext(ctx, `SELECT seq, hash FROM raiwall_admin_audit_head WHERE id = 1`).Scan(&headSeq, &headHash); err != nil {
		return fmt.Errorf("create audit event: read chain head: %w", err)
	}
	seq := headSeq + 1
	hash := control.AuditEventHash(headHash, event)

	if _, err := q.ExecContext(ctx, `INSERT INTO raiwall_admin_audit
		(id, occurred_at, actor_type, actor_id, actor_name, role, action,
		 target_type, target_id, method, path, status_code, request_id, client_ip,
		 user_agent, snapshot_version, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.OccurredAt, event.ActorType, event.ActorID, event.ActorName,
		event.Role, event.Action, event.TargetType, event.TargetID, event.Method,
		event.Path, event.StatusCode, event.RequestID, event.ClientIP, event.UserAgent,
		event.SnapshotVersion, event.Detail,
	); err != nil {
		return fmt.Errorf("create audit event: %w", err)
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO raiwall_admin_audit_chain (seq, event_id, prev_hash, hash)
		VALUES (?, ?, ?, ?)`, seq, event.ID, headHash, hash); err != nil {
		return fmt.Errorf("create audit event: chain row: %w", err)
	}
	if _, err := q.ExecContext(ctx, `UPDATE raiwall_admin_audit_head SET seq = ?, hash = ? WHERE id = 1`, seq, hash); err != nil {
		return fmt.Errorf("create audit event: advance chain head: %w", err)
	}
	return s.appendAuditAnchor(ctx, q, seq, hash)
}

// ListAuditEvents returns matching audit records newest first.
func (s *Store) ListAuditEvents(ctx context.Context, filter control.AuditFilter) ([]control.AuditEvent, error) {
	filter = filter.Normalized()
	query := "SELECT " + auditColumns + " FROM raiwall_admin_audit WHERE 1=1"
	args := make([]any, 0, 6)
	if !filter.From.IsZero() {
		query += " AND occurred_at >= ?"
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		query += " AND occurred_at <= ?"
		args = append(args, filter.To)
	}
	if strings.TrimSpace(filter.Actor) != "" {
		query += " AND (actor_id = ? OR actor_name = ?)"
		args = append(args, filter.Actor, filter.Actor)
	}
	if strings.TrimSpace(filter.Action) != "" {
		query += " AND action = ?"
		args = append(args, filter.Action)
	}
	query += " ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.conn().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []control.AuditEvent
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// DeleteAuditEventsBefore removes audit rows older than cutoff. The chain is
// pruned as a prefix and the retention floor is advanced in the same
// transaction, so verification never mistakes pruning for tampering.
func (s *Store) DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s.tx != nil {
		return pruneAudit(ctx, s.tx, cutoff)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: begin: %w", err)
	}
	removed, err := pruneAudit(ctx, tx, cutoff)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("prune audit events: commit: %w", err)
	}
	return removed, nil
}

func pruneAudit(ctx context.Context, q DBTX, cutoff time.Time) (int64, error) {
	// Everything up to the newest chained event older than cutoff is removed,
	// keeping the surviving chain contiguous.
	var cutoffSeq sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT MAX(c.seq) FROM raiwall_admin_audit_chain c
		JOIN raiwall_admin_audit a ON a.id = c.event_id WHERE a.occurred_at < ?`, cutoff).Scan(&cutoffSeq); err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	var removed int64
	if cutoffSeq.Valid {
		var floorHash string
		if err := q.QueryRowContext(ctx, `SELECT hash FROM raiwall_admin_audit_chain WHERE seq = ?`, cutoffSeq.Int64).Scan(&floorHash); err != nil {
			return 0, fmt.Errorf("prune audit chain: read floor: %w", err)
		}
		result, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE id IN
			(SELECT event_id FROM raiwall_admin_audit_chain WHERE seq <= ?)`, cutoffSeq.Int64)
		if err != nil {
			return 0, fmt.Errorf("prune audit events: %w", err)
		}
		n, _ := result.RowsAffected()
		removed += n
		if _, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit_chain WHERE seq <= ?`, cutoffSeq.Int64); err != nil {
			return 0, fmt.Errorf("prune audit chain: %w", err)
		}
		if err := updateAuditFloor(ctx, q, cutoffSeq.Int64, floorHash); err != nil {
			return 0, err
		}
	}
	result, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE occurred_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	n, _ := result.RowsAffected()
	return removed + n, nil
}

// PruneSnapshots keeps the newest keep snapshots plus the active version.
func (s *Store) PruneSnapshots(ctx context.Context, keep int, activeVersion uint64) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	result, err := s.conn().ExecContext(ctx, `DELETE FROM raiwall_config_snapshots
		WHERE version NOT IN (
			SELECT version FROM raiwall_config_snapshots ORDER BY version DESC LIMIT ?
		) AND version <> ?`, keep, activeVersion)
	if err != nil {
		return 0, fmt.Errorf("prune snapshots: %w", err)
	}
	return result.RowsAffected()
}
