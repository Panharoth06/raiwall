package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ErrSnapshotUnchanged reports that a remote snapshot has the same content as
// the active one, so nothing was swapped. It is a normal convergence event.
var ErrSnapshotUnchanged = errors.New("control: snapshot unchanged")

// RemoteApplyStatus reports the outcome of the most recent remote snapshot
// apply so operators can see what the replica actually accepted.
type RemoteApplyStatus struct {
	AppliedVersion uint64 `json:"applied_version"`
	AppliedHash    string `json:"applied_hash"`
	LastApplyError string `json:"last_apply_error,omitempty"`
}

var (
	// applyMu serializes local deploys, rollbacks, and remote applies so a
	// remote snapshot cannot overwrite a newer local one. Deploy hooks run
	// under this lock, so a hook must never call back into an apply.
	applyMu sync.Mutex
	// remoteStatusMu is separate so /cluster/status never waits on hooks.
	remoteStatusMu sync.Mutex
	remoteStatus   RemoteApplyStatus
)

// RemoteAppliedStatus returns a copy of the last remote apply outcome.
func RemoteAppliedStatus() RemoteApplyStatus {
	remoteStatusMu.Lock()
	defer remoteStatusMu.Unlock()
	return remoteStatus
}

// ApplyRemoteSnapshot applies a snapshot published by another replica exactly
// like a local deploy: verify the publisher's hash when supplied, parse,
// validate, swap atomically, and run the same deploy hooks. Version numbers
// are not ordered because rollbacks legitimately move them backwards; the
// content hash distinguishes a real change from a duplicate notification.
func ApplyRemoteSnapshot(ctx context.Context, raw []byte, expectedHash string) (*ConfigSnapshot, error) {
	actualHash := snapshotHash(raw)
	if expectedHash != "" && actualHash != expectedHash {
		return nil, recordRemoteApplyError(
			fmt.Errorf("snapshot hash mismatch: expected %s, got %s", expectedHash, actualHash))
	}

	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, recordRemoteApplyError(fmt.Errorf("parse cluster snapshot: %w", err))
	}

	snap.RebuildIndex()
	if err := ValidateSnapshot(&snap); err != nil {
		return nil, recordRemoteApplyError(fmt.Errorf("validate cluster snapshot: %w", err))
	}

	applyMu.Lock()
	defer applyMu.Unlock()

	if activeSnapshotHashLocked() == actualHash {
		clearRemoteApplyError()
		return &snap, ErrSnapshotUnchanged
	}

	StoreSnapshot(&snap)
	runDeployHooks(ctx, &snap)
	markRemoteApplied(snap.Version, actualHash)
	return &snap, nil
}

// commitActiveSnapshot swaps a locally compiled snapshot under the same lock
// remote applies use, closing the check-then-store race between them.
func commitActiveSnapshot(ctx context.Context, snap *ConfigSnapshot) {
	applyMu.Lock()
	defer applyMu.Unlock()
	StoreSnapshot(snap)
	runDeployHooks(ctx, snap)
}

func activeSnapshotHashLocked() string {
	active := GetActiveSnapshot()
	if active == nil {
		return ""
	}
	data, err := json.Marshal(active)
	if err != nil {
		return ""
	}
	return snapshotHash(data)
}

func markRemoteApplied(version uint64, hash string) {
	remoteStatusMu.Lock()
	remoteStatus = RemoteApplyStatus{AppliedVersion: version, AppliedHash: hash}
	remoteStatusMu.Unlock()
}

func clearRemoteApplyError() {
	remoteStatusMu.Lock()
	remoteStatus.LastApplyError = ""
	remoteStatusMu.Unlock()
}

func recordRemoteApplyError(err error) error {
	remoteStatusMu.Lock()
	remoteStatus.LastApplyError = err.Error()
	remoteStatusMu.Unlock()
	return err
}

func snapshotHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
