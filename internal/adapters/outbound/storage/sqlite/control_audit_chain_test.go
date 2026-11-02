package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func anchoredAuditStore(t *testing.T, interval int64) *Store {
	t.Helper()
	store := auditTestStore(t)
	store.ConfigureAuditAnchoring(control.AuditAnchorConfig{
		Secret:   []byte("audit-anchor-test-secret-32-bytes"),
		Interval: interval,
		MaxAge:   time.Hour,
	})
	return store
}

func appendAuditEvents(t *testing.T, store *Store, events []control.AuditEvent) {
	t.Helper()
	for _, event := range events {
		require.NoError(t, store.CreateAuditEvent(context.Background(), event))
	}
}

func hourlyAuditEvents(now time.Time, count int) []control.AuditEvent {
	events := make([]control.AuditEvent, 0, count)
	for i := 0; i < count; i++ {
		events = append(events, control.AuditEvent{
			ID:         "e" + string(rune('1'+i)),
			OccurredAt: now.Add(time.Duration(i-count+1) * time.Hour),
			ActorType:  "user",
			ActorName:  "alice",
			Action:     "update",
			Detail:     "event",
		})
	}
	return events
}

func TestAuditChainVerifyAcceptsSignedChain(t *testing.T) {
	store := anchoredAuditStore(t, 2)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 3))

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, report.Valid, report.Reason)
	require.EqualValues(t, 3, report.Checked)
	require.True(t, report.Anchors.Valid, report.Anchors.Reason)
	require.EqualValues(t, 2, report.Anchors.Count, "first event and the interval checkpoint")
}

func TestAuditChainVerifyDetectsModifiedEvent(t *testing.T) {
	store := anchoredAuditStore(t, 100)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 2))

	_, err := store.db.ExecContext(ctx, `UPDATE raiwall_admin_audit SET detail = 'rewritten' WHERE id = 'e1'`)
	require.NoError(t, err)

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, report.Valid)
	require.EqualValues(t, 1, report.BrokenAtSeq)
	require.Contains(t, report.Reason, "event modified")
}

func TestAuditChainVerifyDetectsMissingEvent(t *testing.T) {
	store := anchoredAuditStore(t, 100)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 3))

	_, err := store.db.ExecContext(ctx, `DELETE FROM raiwall_admin_audit WHERE id = 'e2'`)
	require.NoError(t, err)

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, report.Valid, "a missing audit row must not verify")
}

func TestAuditChainVerifyDetectsAnchorTampering(t *testing.T) {
	store := anchoredAuditStore(t, 100)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 2))

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, report.Valid, report.Reason)

	_, err = store.db.ExecContext(ctx, `UPDATE raiwall_admin_audit_anchors SET signature = 'AAAA' WHERE seq = 1`)
	require.NoError(t, err)

	report, err = store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, report.Valid)
	require.False(t, report.Anchors.Valid)
	require.Contains(t, report.Anchors.Reason, "signature")
}

func TestAuditChainVerifySurvivesRetentionPruning(t *testing.T) {
	store := anchoredAuditStore(t, 2)
	ctx := context.Background()
	now := time.Now().UTC()
	events := hourlyAuditEvents(now, 6)
	appendAuditEvents(t, store, events)

	removed, err := store.DeleteAuditEventsBefore(ctx, now.Add(-time.Hour-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 4, removed, "the first four events are pruned as a prefix")

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, report.Valid, report.Reason)
	require.EqualValues(t, 5, report.FirstSeq)
	require.EqualValues(t, 6, report.LastSeq)
	require.True(t, report.Anchors.Valid, report.Anchors.Reason)

	floorSeq, floorHash, err := loadAuditFloor(ctx, store.db)
	require.NoError(t, err)
	require.EqualValues(t, 4, floorSeq)
	require.NotEmpty(t, floorHash)
}

func TestAuditChainVerifyAcceptsFullyPrunedChain(t *testing.T) {
	store := anchoredAuditStore(t, 100)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 2))

	_, err := store.DeleteAuditEventsBefore(ctx, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, report.Valid, report.Reason)
	require.Zero(t, report.Checked)
	require.True(t, report.Anchors.Valid, report.Anchors.Reason)
}

func TestAuditChainVerifyDetectsDeletedAnchor(t *testing.T) {
	store := anchoredAuditStore(t, 2)
	ctx := context.Background()
	appendAuditEvents(t, store, hourlyAuditEvents(time.Now().UTC(), 4))

	// Removing an anchored chain row leaves a sequence gap and the checkpoint
	// no longer matches a retained row.
	_, err := store.db.ExecContext(ctx, `DELETE FROM raiwall_admin_audit_chain WHERE seq = 2`)
	require.NoError(t, err)

	report, err := store.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, report.Valid)
	require.False(t, report.Anchors.Valid)
	require.Contains(t, report.Anchors.Reason, "anchored chain row is missing")
}
