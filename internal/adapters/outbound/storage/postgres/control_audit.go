package postgres

import (
	"context"
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

// CreateAuditEvent appends one audit record.
func (s *ControlStore) CreateAuditEvent(ctx context.Context, event control.AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO raiwall_admin_audit
		(id, occurred_at, actor_type, actor_id, actor_name, role, action,
		 target_type, target_id, method, path, status_code, request_id, client_ip,
		 user_agent, snapshot_version, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		event.ID, event.OccurredAt, event.ActorType, event.ActorID, event.ActorName,
		event.Role, event.Action, event.TargetType, event.TargetID, event.Method,
		event.Path, event.StatusCode, event.RequestID, event.ClientIP, event.UserAgent,
		event.SnapshotVersion, event.Detail,
	)
	if err != nil {
		return fmt.Errorf("create audit event: %w", err)
	}
	return nil
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

// DeleteAuditEventsBefore removes audit rows older than cutoff.
func (s *ControlStore) DeleteAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE occurred_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	return result.RowsAffected()
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
