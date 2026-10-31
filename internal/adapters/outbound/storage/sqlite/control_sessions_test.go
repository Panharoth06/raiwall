package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func TestAdminSessionLifecycle(t *testing.T) {
	store, err := InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	session := control.AdminSession{
		ID:                "sess-1",
		UserID:            "user-1",
		TokenHash:         "hash-1",
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(8 * time.Hour),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		ClientIP:          "203.0.113.5",
		UserAgent:         "test-agent",
	}
	require.NoError(t, store.CreateAdminSession(ctx, session))

	loaded, err := store.GetAdminSessionByTokenHash(ctx, "hash-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", loaded.UserID)
	require.False(t, loaded.RevokedAt.Valid)
	require.WithinDuration(t, session.AbsoluteExpiresAt, loaded.AbsoluteExpiresAt, time.Second)

	touched := now.Add(5 * time.Minute)
	require.NoError(t, store.TouchAdminSession(ctx, "sess-1", touched, touched.Add(8*time.Hour)))
	loaded, err = store.GetAdminSessionByTokenHash(ctx, "hash-1")
	require.NoError(t, err)
	require.WithinDuration(t, touched, loaded.LastSeenAt, time.Second)

	require.NoError(t, store.RevokeAdminSession(ctx, "sess-1", touched))
	loaded, err = store.GetAdminSessionByTokenHash(ctx, "hash-1")
	require.NoError(t, err)
	require.True(t, loaded.RevokedAt.Valid)

	// A second session for the same user is revoked in bulk.
	second := session
	second.ID = "sess-2"
	second.TokenHash = "hash-2"
	require.NoError(t, store.CreateAdminSession(ctx, second))
	require.NoError(t, store.RevokeAdminSessionsForUser(ctx, "user-1", touched))
	loaded, err = store.GetAdminSessionByTokenHash(ctx, "hash-2")
	require.NoError(t, err)
	require.True(t, loaded.RevokedAt.Valid)

	removed, err := store.DeleteExpiredAdminSessions(ctx, now.Add(25*time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 2, removed)

	_, err = store.GetAdminSessionByTokenHash(ctx, "hash-1")
	require.Error(t, err)
}

func TestAdminSessionExpiredRowsRemoved(t *testing.T) {
	store, err := InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.CreateAdminSession(context.Background(), control.AdminSession{
		ID: "sess-old", UserID: "u", TokenHash: "hash-old",
		CreatedAt: now.Add(-48 * time.Hour), LastSeenAt: now.Add(-48 * time.Hour),
		IdleExpiresAt: now.Add(-47 * time.Hour), AbsoluteExpiresAt: now.Add(-24 * time.Hour),
	}))

	removed, err := store.DeleteExpiredAdminSessions(context.Background(), now)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
}
