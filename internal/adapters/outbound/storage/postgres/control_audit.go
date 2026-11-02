package postgres

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
// WithTx the caller's transaction is used; otherwise a private one is opened.
func (s *ControlStore) CreateAuditEvent(ctx context.Context, event control.AuditEvent) error {
	if s.isTx || s.rawDB == nil {
		return s.appendAudit(ctx, s.db, event)
	}
	tx, err := s.rawDB.BeginTx(ctx, nil)
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

func (s *ControlStore) appendAudit(ctx context.Context, q DBTX, event control.AuditEvent) error {
	event.OccurredAt = event.OccurredAt.UTC().Truncate(control.AuditTimePrecision)

	// The row lock on the head serializes concurrent appenders across replicas.
	var headSeq int64
	var headHash string
	if err := q.QueryRowContext(ctx, `SELECT seq, hash FROM raiwall_admin_audit_head WHERE id = 1 FOR UPDATE`).Scan(&headSeq, &headHash); err != nil {
		return fmt.Errorf("create audit event: lock chain head: %w", err)
	}
	seq := headSeq + 1
	hash := control.AuditEventHash(headHash, event)

	if _, err := q.ExecContext(ctx, `INSERT INTO raiwall_admin_audit
		(id, occurred_at, actor_type, actor_id, actor_name, role, action,
		 target_type, target_id, method, path, status_code, request_id, client_ip,
		 user_agent, snapshot_version, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		event.ID, event.OccurredAt, event.ActorType, event.ActorID, event.ActorName,
		event.Role, event.Action, event.TargetType, event.TargetID, event.Method,
		event.Path, event.StatusCode, event.RequestID, event.ClientIP, event.UserAgent,
		event.SnapshotVersion, event.Detail,
	); err != nil {
		return fmt.Errorf("create audit event: %w", err)
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO raiwall_admin_audit_chain (seq, event_id, prev_hash, hash)
		VALUES ($1, $2, $3, $4)`, seq, event.ID, headHash, hash); err != nil {
		return fmt.Errorf("create audit event: chain row: %w", err)
	}
	if _, err := q.ExecContext(ctx, `UPDATE raiwall_admin_audit_head SET seq = $1, hash = $2 WHERE id = 1`, seq, hash); err != nil {
		return fmt.Errorf("create audit event: advance chain head: %w", err)
	}
	return s.appendAuditAnchor(ctx, q, seq, hash)
}

// ListAuditEvents returns matching audit records newest first.
func (s *ControlStore) ListAuditEvents(ctx context.Context, filter control.AuditFilter) ([]control.AuditEvent, error) {
	filter = filter.Normalized()
	query := "SELECT " + auditColumns + " FROM raiwall_admin_audit WHERE 1=1"
	args := make([]any, 0, 6)
	placeholder := func() string { return fmt.Sprintf("$%d", len(args)) }
	if !filter.From.IsZero() {
		args = append(args, filter.From)
		query += " AND occurred_at >= " + placeholder()
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To)
		query += " AND occurred_at <= " + placeholder()
	}
	if strings.TrimSpace(filter.Actor) != "" {
		args = append(args, filter.Actor, filter.Actor)
		query += fmt.Sprintf(" AND (actor_id = $%d OR actor_name = $%d)", len(args)-1, len(args))
	}
	if strings.TrimSpace(filter.Action) != "" {
		args = append(args, filter.Action)
		query += " AND action = " + placeholder()
	}
	args = append(args, filter.Limit, filter.Offset)
	query += fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
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
func (s *ControlStore) DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s.isTx || s.rawDB == nil {
		return pruneAudit(ctx, s.db, cutoff)
	}
	tx, err := s.rawDB.BeginTx(ctx, nil)
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
		JOIN raiwall_admin_audit a ON a.id = c.event_id WHERE a.occurred_at < $1`, cutoff).Scan(&cutoffSeq); err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	var removed int64
	if cutoffSeq.Valid {
		var floorHash string
		if err := q.QueryRowContext(ctx, `SELECT hash FROM raiwall_admin_audit_chain WHERE seq = $1`, cutoffSeq.Int64).Scan(&floorHash); err != nil {
			return 0, fmt.Errorf("prune audit chain: read floor: %w", err)
		}
		result, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE id IN
			(SELECT event_id FROM raiwall_admin_audit_chain WHERE seq <= $1)`, cutoffSeq.Int64)
		if err != nil {
			return 0, fmt.Errorf("prune audit events: %w", err)
		}
		n, _ := result.RowsAffected()
		removed += n
		if _, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit_chain WHERE seq <= $1`, cutoffSeq.Int64); err != nil {
			return 0, fmt.Errorf("prune audit chain: %w", err)
		}
		if err := updateAuditFloor(ctx, q, cutoffSeq.Int64, floorHash); err != nil {
			return 0, err
		}
	}
	result, err := q.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE occurred_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	n, _ := result.RowsAffected()
	return removed + n, nil
}

// PruneSnapshots keeps the newest keep snapshots plus the active version.
func (s *ControlStore) PruneSnapshots(ctx context.Context, keep int, activeVersion uint64) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM raiwall_config_snapshots
		WHERE version NOT IN (
			SELECT version FROM raiwall_config_snapshots ORDER BY version DESC LIMIT $1
		) AND version <> $2`, keep, activeVersion)
	if err != nil {
		return 0, fmt.Errorf("prune snapshots: %w", err)
	}
	return result.RowsAffected()
}
