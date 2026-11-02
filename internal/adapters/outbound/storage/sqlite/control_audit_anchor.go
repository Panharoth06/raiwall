package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// ConfigureAuditAnchoring enables Ed25519 checkpoints for this store.
func (s *Store) ConfigureAuditAnchoring(cfg control.AuditAnchorConfig) {
	s.auditAnchor = control.NewAuditAnchorer(cfg)
}

// appendAuditAnchor signs a checkpoint when the configured interval elapsed.
// It runs inside the same transaction as the event and chain row.
func (s *Store) appendAuditAnchor(ctx context.Context, q DBTX, seq int64, hash string) error {
	if s.auditAnchor == nil {
		return nil
	}
	last, hasLast, err := loadLastAuditAnchor(ctx, q)
	if err != nil {
		return fmt.Errorf("create audit event: load last anchor: %w", err)
	}
	now := time.Now().UTC()
	if !s.auditAnchor.ShouldAnchor(seq, now, last.SignedAt, hasLast) {
		return nil
	}
	anchor := s.auditAnchor.Sign(seq, hash, now)
	if _, err := q.ExecContext(ctx, `INSERT INTO raiwall_admin_audit_anchors
		(seq, hash, signed_at, public_key, signature) VALUES (?, ?, ?, ?, ?)`,
		anchor.Seq, anchor.Hash, anchor.SignedAt, anchor.PublicKey, anchor.Signature); err != nil {
		return fmt.Errorf("create audit event: insert anchor: %w", err)
	}
	return nil
}

func loadLastAuditAnchor(ctx context.Context, q DBTX) (control.AuditAnchor, bool, error) {
	var anchor control.AuditAnchor
	err := q.QueryRowContext(ctx, `SELECT seq, hash, signed_at, public_key, signature
		FROM raiwall_admin_audit_anchors ORDER BY seq DESC LIMIT 1`).Scan(
		&anchor.Seq, &anchor.Hash, &anchor.SignedAt, &anchor.PublicKey, &anchor.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return control.AuditAnchor{}, false, nil
	}
	if err != nil {
		return control.AuditAnchor{}, false, err
	}
	return anchor, true, nil
}

// verifyAuditAnchors checks every checkpoint against its signature and the
// retained chain window, then merges the result into the chain report.
func (s *Store) verifyAuditAnchors(ctx context.Context, q DBTX, report *control.AuditChainReport, floorSeq, headSeq int64) error {
	var current ed25519.PublicKey
	if s.auditAnchor != nil {
		current = s.auditAnchor.PublicKey()
	}
	// The retained window is defined by the recorded floor and head, not by the
	// rows that happened to verify before the first break.
	verifier := control.NewAuditAnchorVerifier(current, floorSeq+1, headSeq)

	rows, err := q.QueryContext(ctx, `SELECT seq, hash, signed_at, public_key, signature
		FROM raiwall_admin_audit_anchors ORDER BY seq ASC`)
	if err != nil {
		return fmt.Errorf("verify audit chain: list anchors: %w", err)
	}
	defer rows.Close()

	var anchors []control.AuditAnchor
	for rows.Next() {
		var anchor control.AuditAnchor
		if err := rows.Scan(&anchor.Seq, &anchor.Hash, &anchor.SignedAt, &anchor.PublicKey, &anchor.Signature); err != nil {
			return fmt.Errorf("verify audit chain: scan anchor: %w", err)
		}
		anchors = append(anchors, anchor)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("verify audit chain: %w", err)
	}
	rows.Close()

	for _, anchor := range anchors {
		chainHash, err := anchoredChainHash(ctx, q, anchor.Seq)
		if err != nil {
			return err
		}
		verifier.Add(anchor, chainHash)
	}
	report.Anchors = verifier.Finish()
	if !report.Anchors.Valid {
		report.Valid = false
		if report.Reason == "" {
			report.Reason = report.Anchors.Reason
		}
	}
	return nil
}

func anchoredChainHash(ctx context.Context, q DBTX, seq int64) (string, error) {
	var hash string
	err := q.QueryRowContext(ctx, `SELECT hash FROM raiwall_admin_audit_chain WHERE seq = ?`, seq).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("verify audit chain: read anchored row: %w", err)
	}
	return hash, nil
}

// updateAuditFloor records the last chain entry removed by retention.
func updateAuditFloor(ctx context.Context, q DBTX, seq int64, hash string) error {
	if _, err := q.ExecContext(ctx, `UPDATE raiwall_admin_audit_floor SET seq = ?, hash = ? WHERE id = 1`, seq, hash); err != nil {
		return fmt.Errorf("prune audit chain: advance floor: %w", err)
	}
	return nil
}

// loadAuditFloor returns the retention marker.
func loadAuditFloor(ctx context.Context, q DBTX) (int64, string, error) {
	var seq int64
	var hash string
	if err := q.QueryRowContext(ctx, `SELECT seq, hash FROM raiwall_admin_audit_floor WHERE id = 1`).Scan(&seq, &hash); err != nil {
		return 0, "", fmt.Errorf("read audit floor: %w", err)
	}
	return seq, hash, nil
}
