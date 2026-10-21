package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Snapshots

func (s *ControlStore) CreateSnapshot(ctx context.Context, snap control.ConfigSnapshotRecord) (control.ConfigSnapshotRecord, error) {
	query := `INSERT INTO raiwall_config_snapshots (snapshot_data, author, description, created_at)
	          VALUES ($1, $2, $3, $4)
	          RETURNING version, snapshot_data, author, description, created_at`
	var r control.ConfigSnapshotRecord
	err := s.db.QueryRowContext(ctx, query, snap.SnapshotData, snap.Author, snap.Description, snap.CreatedAt).Scan(
		&r.Version, &r.SnapshotData, &r.Author, &r.Description, &r.CreatedAt,
	)
	if err != nil {
		return control.ConfigSnapshotRecord{}, fmt.Errorf("create snapshot: %w", err)
	}
	return r, nil
}

func (s *ControlStore) GetSnapshotByVersion(ctx context.Context, version int64) (control.ConfigSnapshotRecord, error) {
	query := `SELECT version, snapshot_data, author, description, created_at
	          FROM raiwall_config_snapshots WHERE version = $1 LIMIT 1`
	var r control.ConfigSnapshotRecord
	err := s.db.QueryRowContext(ctx, query, version).Scan(
		&r.Version, &r.SnapshotData, &r.Author, &r.Description, &r.CreatedAt,
	)
	if err != nil {
		return control.ConfigSnapshotRecord{}, fmt.Errorf("get snapshot by version %d: %w", version, err)
	}
	return r, nil
}

func (s *ControlStore) GetLatestSnapshot(ctx context.Context) (control.ConfigSnapshotRecord, error) {
	query := `SELECT version, snapshot_data, author, description, created_at
	          FROM raiwall_config_snapshots ORDER BY version DESC LIMIT 1`
	var r control.ConfigSnapshotRecord
	err := s.db.QueryRowContext(ctx, query).Scan(
		&r.Version, &r.SnapshotData, &r.Author, &r.Description, &r.CreatedAt,
	)
	if err != nil {
		return control.ConfigSnapshotRecord{}, fmt.Errorf("get latest snapshot: %w", err)
	}
	return r, nil
}

func (s *ControlStore) ListSnapshots(ctx context.Context) ([]control.ConfigSnapshotRecord, error) {
	query := `SELECT version, snapshot_data, author, description, created_at
	          FROM raiwall_config_snapshots ORDER BY version DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()

	var list []control.ConfigSnapshotRecord
	for rows.Next() {
		var r control.ConfigSnapshotRecord
		if err := rows.Scan(&r.Version, &r.SnapshotData, &r.Author, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		list = append(list, r)
	}
	return list, rows.Err()
}
