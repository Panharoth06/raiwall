package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

// Hand-written SQL inside WithTx must run on the transaction, so a rollback
// discards it.
func TestWithTxRollsBackHandWrittenSQL(t *testing.T) {
	store, err := InitDB("file:" + filepath.Join(t.TempDir(), "control.db") + "?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	boom := errors.New("boom")
	err = store.WithTx(ctx, func(tx control.ControlStore) error {
		require.NoError(t, tx.CreateAuditEvent(ctx, control.AuditEvent{ID: "tx1", OccurredAt: time.Now().UTC(), Action: "create"}))
		return boom
	})
	require.ErrorIs(t, err, boom)

	events, err := store.ListAuditEvents(ctx, control.AuditFilter{})
	require.NoError(t, err)
	require.Empty(t, events, "rolled-back write must not persist")

	require.NoError(t, store.WithTx(ctx, func(tx control.ControlStore) error {
		return tx.CreateAuditEvent(ctx, control.AuditEvent{ID: "tx2", OccurredAt: time.Now().UTC(), Action: "create"})
	}))
	events, err = store.ListAuditEvents(ctx, control.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, events, 1)
}
