package control

import (
	"sync/atomic"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// SnapshotManager manages atomic, lock-free access to ConfigSnapshot.
type SnapshotManager struct {
	current atomic.Pointer[ConfigSnapshot]
}

// globalSnapshot is the default package-level snapshot manager.
var globalSnapshot = NewSnapshotManager(NewConfigSnapshot(1, ModeDefense, nil))

// NewSnapshotManager creates a new SnapshotManager instance with optional initial snapshot.
func NewSnapshotManager(initial *ConfigSnapshot) *SnapshotManager {
	sm := &SnapshotManager{}
	if initial != nil {
		sm.StoreSnapshot(initial)
	}
	return sm
}

// StoreSnapshot atomically stores a new ConfigSnapshot.
func (sm *SnapshotManager) StoreSnapshot(newSnap *ConfigSnapshot) {
	sm.current.Store(newSnap)
}

// LoadSnapshot atomically loads the current ConfigSnapshot.
func (sm *SnapshotManager) LoadSnapshot() *ConfigSnapshot {
	return sm.current.Load()
}

// StoreSnapshot updates the package-level global snapshot.
func StoreSnapshot(newSnap *ConfigSnapshot) {
	globalSnapshot.StoreSnapshot(newSnap)
}

// LoadSnapshot retrieves the package-level global snapshot.
func LoadSnapshot() *ConfigSnapshot {
	return globalSnapshot.LoadSnapshot()
}

// GetActiveSnapshot returns the current active global snapshot.
func GetActiveSnapshot() *ConfigSnapshot {
	return LoadSnapshot()
}

// SetActiveSnapshot atomically sets the global active snapshot.
func SetActiveSnapshot(newSnap *ConfigSnapshot) {
	StoreSnapshot(newSnap)
}

// SnapshotMatrixSource resolves the effective SemanticMatrix for an application
// from the current global active config snapshot. Live config applies are picked
// up automatically because the snapshot reference is swapped atomically.
type SnapshotMatrixSource struct{}

// MatrixFor resolves the semantic matrix from the active snapshot.
func (SnapshotMatrixSource) MatrixFor(appID string) waf.SemanticMatrix {
	if snap := LoadSnapshot(); snap != nil {
		return snap.SemanticMatrixFor(appID)
	}
	return waf.DefaultMatrix()
}
