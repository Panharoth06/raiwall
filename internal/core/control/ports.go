package control

import (
	"context"
)

// ControlStorePort defines the driven port for configuration persistence.
type ControlStorePort interface {
	CompileSnapshot(ctx context.Context) (*ConfigSnapshot, error)
	RollbackSnapshot(ctx context.Context, version int64) (*ConfigSnapshot, error)
}

// ClusterPublisherPort defines the driven port for publishing config updates across nodes.
type ClusterPublisherPort interface {
	PublishVersion(ctx context.Context, version uint64) error
	PublishSnapshot(ctx context.Context, snap *ConfigSnapshot, author string) error
}

// SnapshotManagerPort defines the port for managing active snapshots.
type SnapshotManagerPort interface {
	StoreSnapshot(newSnap *ConfigSnapshot)
	LoadSnapshot() *ConfigSnapshot
}
