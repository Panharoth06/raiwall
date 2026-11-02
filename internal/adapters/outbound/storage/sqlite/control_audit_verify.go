package sqlite

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// VerifyAuditChain walks the chain in sequence order and reports the first
// break. Retention pruning removes a prefix of the chain, which is accepted and
// cross-checked against the recorded floor.
func (s *Store) VerifyAuditChain(ctx context.Context) (control.AuditChainReport, error) {
	q := s.conn()
	var unchained int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM raiwall_admin_audit a
		WHERE NOT EXISTS (SELECT 1 FROM raiwall_admin_audit_chain c WHERE c.event_id = a.id)`).Scan(&unchained); err != nil {
		return control.AuditChainReport{}, fmt.Errorf("verify audit chain: count unchained: %w", err)
	}

	rows, err := q.QueryContext(ctx, `SELECT c.seq, c.prev_hash, c.hash,
		a.id, a.occurred_at, a.actor_type, a.actor_id, a.actor_name, a.role, a.action,
		a.target_type, a.target_id, a.method, a.path, a.status_code, a.request_id, a.client_ip,
		a.user_agent, a.snapshot_version, a.detail
		FROM raiwall_admin_audit_chain c
		JOIN raiwall_admin_audit a ON a.id = c.event_id
		ORDER BY c.seq ASC`)
	if err != nil {
		return control.AuditChainReport{}, fmt.Errorf("verify audit chain: %w", err)
	}
	defer rows.Close()

	verifier := control.NewAuditChainVerifier(unchained)
	for rows.Next() {
		var row control.AuditChainRow
		e := &row.Event
		if err := rows.Scan(&row.Seq, &row.PrevHash, &row.Hash,
			&e.ID, &e.OccurredAt, &e.ActorType, &e.ActorID, &e.ActorName, &e.Role, &e.Action,
			&e.TargetType, &e.TargetID, &e.Method, &e.Path, &e.StatusCode, &e.RequestID, &e.ClientIP,
			&e.UserAgent, &e.SnapshotVersion, &e.Detail); err != nil {
			return control.AuditChainReport{}, fmt.Errorf("verify audit chain: scan: %w", err)
		}
		verifier.Add(row)
	}
	if err := rows.Err(); err != nil {
		return control.AuditChainReport{}, fmt.Errorf("verify audit chain: %w", err)
	}
	rows.Close()

	var headSeq int64
	var headHash string
	if err := q.QueryRowContext(ctx, `SELECT seq, hash FROM raiwall_admin_audit_head WHERE id = 1`).Scan(&headSeq, &headHash); err != nil {
		return control.AuditChainReport{}, fmt.Errorf("verify audit chain: read head: %w", err)
	}
	floorSeq, floorHash, err := loadAuditFloor(ctx, q)
	if err != nil {
		return control.AuditChainReport{}, err
	}
	report := verifier.Finish(headSeq, headHash, floorSeq, floorHash)
	if err := s.verifyAuditAnchors(ctx, q, &report, floorSeq, headSeq); err != nil {
		return control.AuditChainReport{}, err
	}
	return report, nil
}
