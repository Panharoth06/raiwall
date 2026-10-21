package control

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// DeploySnapshot compiles draft records, validates them, commits a versioned snapshot,
// and atomically updates the active data plane snapshot pointer.
func DeploySnapshot(ctx context.Context, store ControlStore, author, description string) (*ConfigSnapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}

	snap, err := CompileSnapshot(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("pre-flight validation failed: %w", err)
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize snapshot: %w", err)
	}

	if author == "" {
		author = "system"
	}

	saved, err := store.CreateSnapshot(ctx, ConfigSnapshotRecord{
		SnapshotData: string(data),
		Author:       author,
		Description:  description,
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save snapshot history: %w", err)
	}

	snap.Version = uint64(saved.Version)
	StoreSnapshot(snap)

	return snap, nil
}

// RollbackToVersion retrieves a historical snapshot by version from storage,
// deserializes, validates, and atomically swaps it as the active configuration.
func RollbackToVersion(ctx context.Context, store ControlStore, targetVersion uint64) (*ConfigSnapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}

	record, err := store.GetSnapshotByVersion(ctx, int64(targetVersion))
	if err != nil {
		return nil, fmt.Errorf("snapshot version %d not found: %w", targetVersion, err)
	}

	var snap ConfigSnapshot
	if err := json.Unmarshal([]byte(record.SnapshotData), &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot data for version %d: %w", targetVersion, err)
	}

	snap.RebuildIndex()

	if err := ValidateSnapshot(&snap); err != nil {
		return nil, fmt.Errorf("historical snapshot validation failed: %w", err)
	}

	snap.Version = targetVersion
	StoreSnapshot(&snap)

	return &snap, nil
}

// ListSnapshotHistory returns historical snapshots recorded in storage.
func ListSnapshotHistory(ctx context.Context, store ControlStore) ([]ConfigSnapshotRecord, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}
	return store.ListSnapshots(ctx)
}
