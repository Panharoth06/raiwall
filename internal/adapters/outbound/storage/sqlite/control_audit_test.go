package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func auditTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestAuditEventsAppendListFilterPrune(t *testing.T) {
	store := auditTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	events := []control.AuditEvent{
		{ID: "a1", OccurredAt: now.Add(-2 * time.Hour), ActorType: "user", ActorID: "u1", ActorName: "alice", Role: "admin", Action: "login_success", ClientIP: "203.0.113.5"},
		{ID: "a2", OccurredAt: now.Add(-time.Hour), ActorType: "user", ActorID: "u1", ActorName: "alice", Role: "admin", Action: "update", TargetType: "site", TargetID: "app-1", Method: "PUT", Path: "/sites/app-1", StatusCode: 200},
		{ID: "a3", OccurredAt: now, ActorType: "anonymous", ActorName: "bob", Action: "login_failure", ClientIP: "203.0.113.9", StatusCode: 401},
	}
	for _, event := range events {
		require.NoError(t, store.CreateAuditEvent(ctx, event))
	}

	all, err := store.ListAuditEvents(ctx, control.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, all, 3)
	require.Equal(t, "a3", all[0].ID, "newest first")

	byActor, err := store.ListAuditEvents(ctx, control.AuditFilter{Actor: "alice"})
	require.NoError(t, err)
	require.Len(t, byActor, 2)

	byAction, err := store.ListAuditEvents(ctx, control.AuditFilter{Action: "login_failure"})
	require.NoError(t, err)
	require.Len(t, byAction, 1)
	require.Equal(t, 401, byAction[0].StatusCode)

	byTime, err := store.ListAuditEvents(ctx, control.AuditFilter{From: now.Add(-90 * time.Minute)})
	require.NoError(t, err)
	require.Len(t, byTime, 2)

	page, err := store.ListAuditEvents(ctx, control.AuditFilter{Limit: 1, Offset: 1})
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, "a2", page[0].ID)

	removed, err := store.DeleteAuditEventsBefore(ctx, now.Add(-90*time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
	remaining, err := store.ListAuditEvents(ctx, control.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, remaining, 2)
}

func TestPruneSnapshotsKeepsNewestAndActive(t *testing.T) {
	store := auditTestStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := store.CreateSnapshot(ctx, control.ConfigSnapshotRecord{
			SnapshotData: `{"version":1}`,
			Author:       "test",
			CreatedAt:    time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	removed, err := store.PruneSnapshots(ctx, 2, 1)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed, "only versions outside the newest two and the active version are removed")

	snapshots, err := store.ListSnapshots(ctx)
	require.NoError(t, err)
	versions := make([]int64, 0, len(snapshots))
	for _, snap := range snapshots {
		versions = append(versions, snap.Version)
	}
	require.ElementsMatch(t, []int64{1, 4, 5}, versions)

	removed, err = store.PruneSnapshots(ctx, 0, 1)
	require.NoError(t, err)
	require.Zero(t, removed, "keep=0 disables pruning")
}
