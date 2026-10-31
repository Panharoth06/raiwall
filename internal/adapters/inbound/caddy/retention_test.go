package caddy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

func TestPruneRetention(t *testing.T) {
	store, err := sqlite.InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	defer store.Close()

	previous := control.GetActiveSnapshot()
	control.StoreSnapshot(control.NewConfigSnapshot(1, control.ModeDefense, nil))
	t.Cleanup(func() { control.StoreSnapshot(previous) })

	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		_, err := store.CreateSnapshot(ctx, control.ConfigSnapshotRecord{
			SnapshotData: `{"version":1}`, Author: "test", CreatedAt: now,
		})
		require.NoError(t, err)
	}
	require.NoError(t, store.CreateAuditEvent(ctx, control.AuditEvent{
		ID: "old", OccurredAt: now.Add(-48 * time.Hour), Action: "update",
	}))
	require.NoError(t, store.CreateAuditEvent(ctx, control.AuditEvent{
		ID: "recent", OccurredAt: now.Add(-time.Hour), Action: "update",
	}))
	require.NoError(t, store.CreateAdminSession(ctx, control.AdminSession{
		ID: "sess", UserID: "u", TokenHash: "h",
		CreatedAt: now.Add(-48 * time.Hour), LastSeenAt: now.Add(-48 * time.Hour),
		IdleExpiresAt: now.Add(-47 * time.Hour), AbsoluteExpiresAt: now.Add(-24 * time.Hour),
	}))

	mw := &Middleware{
		controlStore: store,
		ControlConfig: &ControlSettings{
			SnapshotRetention: 2,
			AuditRetention:    caddy.Duration(24 * time.Hour),
		},
	}
	mw.pruneRetention(ctx)

	snapshots, err := store.ListSnapshots(ctx)
	require.NoError(t, err)
	versions := make([]int64, 0, len(snapshots))
	for _, snap := range snapshots {
		versions = append(versions, snap.Version)
	}
	require.ElementsMatch(t, []int64{1, 4, 5}, versions)

	audit, err := store.ListAuditEvents(ctx, control.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, audit, 1)
	require.Equal(t, "recent", audit[0].ID)

	_, err = store.GetAdminSessionByTokenHash(ctx, "h")
	require.Error(t, err, "expired sessions are pruned")
}
