package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// isolateRemoteApply restores the package-level snapshot, deploy hooks, and
// remote-apply status after a test so tests in this package stay independent.
func isolateRemoteApply(t *testing.T) {
	t.Helper()
	previous := GetActiveSnapshot()

	deployHooksMu.Lock()
	previousHooks := deployHooks
	deployHooks = nil
	deployHooksMu.Unlock()

	t.Cleanup(func() {
		StoreSnapshot(previous)
		deployHooksMu.Lock()
		deployHooks = previousHooks
		deployHooksMu.Unlock()
		remoteStatusMu.Lock()
		remoteStatus = RemoteApplyStatus{}
		remoteStatusMu.Unlock()
	})
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func appSnapshot(version uint64, host string) *ConfigSnapshot {
	return NewConfigSnapshot(version, ModeDefense, []*AppConfig{{
		ID:        "app-" + host,
		Name:      host,
		Hostnames: []string{host},
		Mode:      ModeDefense,
		Upstreams: []UpstreamTarget{{Dial: "127.0.0.1:8000"}},
	}})
}

func TestApplyRemoteSnapshotAppliesAndRunsHooks(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	applied := make(chan uint64, 1)
	RegisterDeployHook(func(_ context.Context, snap *ConfigSnapshot) {
		applied <- snap.Version
	})

	snap := NewConfigSnapshot(2, ModeDefense, nil)
	raw, err := json.Marshal(snap)
	require.NoError(t, err)

	got, err := ApplyRemoteSnapshot(context.Background(), raw, hashOf(raw))
	require.NoError(t, err)
	require.Equal(t, uint64(2), got.Version)
	require.Equal(t, uint64(2), GetActiveSnapshot().Version)

	select {
	case version := <-applied:
		require.Equal(t, uint64(2), version)
	case <-time.After(time.Second):
		t.Fatal("deploy hooks did not run for a remote snapshot")
	}

	status := RemoteAppliedStatus()
	require.Equal(t, uint64(2), status.AppliedVersion)
	require.Equal(t, hashOf(raw), status.AppliedHash)
	require.Empty(t, status.LastApplyError)
}

// A fresh HA pair both run the built-in version 1 default; the first real
// deploy is also version 1 and must not be discarded as stale.
func TestApplyRemoteSnapshotAppliesFirstDeployAtVersionOne(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	raw, err := json.Marshal(appSnapshot(1, "first.example.com"))
	require.NoError(t, err)

	got, err := ApplyRemoteSnapshot(context.Background(), raw, hashOf(raw))
	require.NoError(t, err)
	require.Equal(t, uint64(1), got.Version)
	_, found := GetActiveSnapshot().GetAppForHost("first.example.com")
	require.True(t, found)
}

// Rollbacks move the version backwards; peers must still apply them.
func TestApplyRemoteSnapshotAppliesRollbackToOlderVersion(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(appSnapshot(5, "new.example.com"))

	raw, err := json.Marshal(appSnapshot(3, "old.example.com"))
	require.NoError(t, err)

	got, err := ApplyRemoteSnapshot(context.Background(), raw, hashOf(raw))
	require.NoError(t, err)
	require.Equal(t, uint64(3), got.Version)
	require.Equal(t, uint64(3), GetActiveSnapshot().Version)
	_, found := GetActiveSnapshot().GetAppForHost("old.example.com")
	require.True(t, found)
}

func TestApplyRemoteSnapshotNoOpWhenContentUnchanged(t *testing.T) {
	isolateRemoteApply(t)
	active := NewConfigSnapshot(2, ModeDefense, nil)
	StoreSnapshot(active)

	var hooks atomic.Int32
	RegisterDeployHook(func(context.Context, *ConfigSnapshot) { hooks.Add(1) })

	raw, err := json.Marshal(active)
	require.NoError(t, err)

	got, err := ApplyRemoteSnapshot(context.Background(), raw, hashOf(raw))
	require.ErrorIs(t, err, ErrSnapshotUnchanged)
	require.NotNil(t, got)
	require.Zero(t, hooks.Load(), "an unchanged snapshot must not run deploy hooks")
}

func TestApplyRemoteSnapshotRejectsHashMismatch(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	raw, err := json.Marshal(NewConfigSnapshot(2, ModeDefense, nil))
	require.NoError(t, err)

	_, err = ApplyRemoteSnapshot(context.Background(), raw, hashOf([]byte("tampered")))
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash mismatch")
	require.Equal(t, uint64(1), GetActiveSnapshot().Version)

	status := RemoteAppliedStatus()
	require.NotEmpty(t, status.LastApplyError)
	require.Zero(t, status.AppliedVersion)
}

func TestApplyRemoteSnapshotRecordsParseFailure(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	_, err := ApplyRemoteSnapshot(context.Background(), []byte("{not json"), "")
	require.Error(t, err)
	require.NotEmpty(t, RemoteAppliedStatus().LastApplyError)
	require.Equal(t, uint64(1), GetActiveSnapshot().Version)
}

func TestApplyRemoteSnapshotSkipsHashCheckWithoutExpectedHash(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	raw, err := json.Marshal(appSnapshot(3, "poll.example.com"))
	require.NoError(t, err)

	got, err := ApplyRemoteSnapshot(context.Background(), raw, "")
	require.NoError(t, err)
	require.Equal(t, uint64(3), got.Version)
	require.Equal(t, uint64(3), GetActiveSnapshot().Version)
}

// A remote apply must wait for an in-flight local deploy instead of overwriting
// it after the version check.
func TestLocalDeploySerializesWithRemoteApply(t *testing.T) {
	isolateRemoteApply(t)
	StoreSnapshot(NewConfigSnapshot(1, ModeDefense, nil))

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	RegisterDeployHook(func(context.Context, *ConfigSnapshot) {
		once.Do(func() { close(entered) })
		<-release
	})

	localDone := make(chan struct{})
	go func() {
		commitActiveSnapshot(context.Background(), NewConfigSnapshot(6, ModeDefense, nil))
		close(localDone)
	}()
	<-entered

	raw, err := json.Marshal(NewConfigSnapshot(5, ModeDefense, nil))
	require.NoError(t, err)
	remoteDone := make(chan error, 1)
	go func() {
		_, applyErr := ApplyRemoteSnapshot(context.Background(), raw, hashOf(raw))
		remoteDone <- applyErr
	}()

	select {
	case <-remoteDone:
		t.Fatal("remote apply ran while a local deploy held the apply lock")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-localDone
	require.NoError(t, <-remoteDone)
	require.Equal(t, uint64(5), GetActiveSnapshot().Version)
}
