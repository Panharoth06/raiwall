package config

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/pkg/control/db"
)

// DeploySnapshot compiles draft SQLite records, validates them, commits a versioned snapshot,
// and atomically updates the active data plane snapshot pointer.
func DeploySnapshot(ctx context.Context, store *db.Store, author, description string) (*ConfigSnapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}

	// 1. Compile and pre-flight validate
	snap, err := CompileSnapshot(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("pre-flight validation failed: %w", err)
	}

	// 2. Serialize snapshot
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize snapshot: %w", err)
	}

	if author == "" {
		author = "system"
	}

	// 3. Persist to raiwall_config_snapshots
	saved, err := store.CreateSnapshot(ctx, db.CreateSnapshotParams{
		SnapshotData: string(data),
		Author:       author,
		Description:  description,
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save snapshot history: %w", err)
	}

	// 4. Update snapshot version with persisted version
	snap.Version = uint64(saved.Version)

	// 5. Atomic lock-free pointer swap
	StoreSnapshot(snap)

	return snap, nil
}

// RollbackToVersion retrieves a historical snapshot by version from SQLite,
// deserializes, validates, and atomically swaps it as the active configuration.
func RollbackToVersion(ctx context.Context, store *db.Store, targetVersion uint64) (*ConfigSnapshot, error) {
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

	// Pre-flight validate restored snapshot
	if err := ValidateSnapshot(&snap); err != nil {
		return nil, fmt.Errorf("historical snapshot validation failed: %w", err)
	}

	snap.Version = targetVersion

	// Atomic lock-free pointer swap
	StoreSnapshot(&snap)

	return &snap, nil
}

// ListSnapshotHistory returns historical snapshots recorded in SQLite.
func ListSnapshotHistory(ctx context.Context, store *db.Store) ([]db.RaiwallConfigSnapshot, error) {
	if store == nil {
		return nil, fmt.Errorf("database store cannot be nil")
	}
	return store.ListSnapshots(ctx)
}

// GetActiveSnapshot returns the currently active data plane snapshot.
func GetActiveSnapshot() *ConfigSnapshot {
	return LoadSnapshot()
}
