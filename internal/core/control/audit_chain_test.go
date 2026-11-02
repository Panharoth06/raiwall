package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func chainedEvents(prev string, events ...AuditEvent) []AuditChainRow {
	rows := make([]AuditChainRow, 0, len(events))
	hash := prev
	for i, event := range events {
		row := AuditChainRow{Event: event, Seq: int64(i + 1), PrevHash: hash}
		row.Hash = AuditEventHash(row.PrevHash, row.Event)
		rows = append(rows, row)
		hash = row.Hash
	}
	return rows
}

func verifyRows(rows []AuditChainRow, headSeq int64, headHash string, floorSeq int64, floorHash string) AuditChainReport {
	verifier := NewAuditChainVerifier(0)
	for _, row := range rows {
		verifier.Add(row)
	}
	return verifier.Finish(headSeq, headHash, floorSeq, floorHash)
}

func testAuditEvents() []AuditEvent {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	return []AuditEvent{
		{ID: "e1", OccurredAt: at, ActorType: "user", ActorName: "alice", Action: "login_success"},
		{ID: "e2", OccurredAt: at.Add(time.Second), ActorType: "user", ActorName: "alice", Role: "admin", Action: "update", TargetType: "site", TargetID: "app-1", StatusCode: 200},
		{ID: "e3", OccurredAt: at.Add(2 * time.Second), ActorType: "anonymous", Action: "login_failure", StatusCode: 401},
	}
}

func TestAuditEventHashIsDeterministicAndFieldBound(t *testing.T) {
	event := testAuditEvents()[1]
	first := AuditEventHash("prev", event)
	require.Equal(t, first, AuditEventHash("prev", event), "hash must be deterministic")

	changed := event
	changed.Detail = "tampered"
	require.NotEqual(t, first, AuditEventHash("prev", changed))
	require.NotEqual(t, first, AuditEventHash("other-prev", event), "prev hash must participate")
}

func TestAuditChainVerifierAcceptsIntactChain(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	report := verifyRows(rows, 3, rows[2].Hash, 0, "")
	require.True(t, report.Valid, report.Reason)
	require.EqualValues(t, 3, report.Checked)
	require.EqualValues(t, 1, report.FirstSeq)
	require.EqualValues(t, 3, report.LastSeq)
	require.Zero(t, report.Unchained)
}

func TestAuditChainVerifierDetectsModifiedEvent(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	rows[1].Event.Detail = "rewritten after the fact"
	report := verifyRows(rows, 3, rows[2].Hash, 0, "")
	require.False(t, report.Valid)
	require.EqualValues(t, 2, report.BrokenAtSeq)
	require.Equal(t, "e2", report.BrokenEventID)
	require.Contains(t, report.Reason, "event modified")
}

func TestAuditChainVerifierDetectsRemovedMiddleEvent(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	gapped := []AuditChainRow{rows[0], rows[2]}
	report := verifyRows(gapped, 3, rows[2].Hash, 0, "")
	require.False(t, report.Valid)
	require.Contains(t, report.Reason, "sequence gap")
}

func TestAuditChainVerifierDetectsTruncatedTail(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	report := verifyRows(rows[:2], 3, rows[2].Hash, 0, "")
	require.False(t, report.Valid)
	require.Contains(t, report.Reason, "trailing events removed")
}

func TestAuditChainVerifierAcceptsRetentionPrefix(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	// Retention removed sequences 1 and 2; the floor records sequence 2.
	retained := rows[2:]
	report := verifyRows(retained, 3, rows[2].Hash, 2, rows[1].Hash)
	require.True(t, report.Valid, report.Reason)
	require.EqualValues(t, 3, report.FirstSeq)

	// A missing floor marker makes the surviving prefix unverifiable.
	broken := verifyRows(retained, 3, rows[2].Hash, 0, "")
	require.False(t, broken.Valid)

	// Removing the floor row while keeping the floor value is detected too.
	movedFloor := verifyRows(retained, 3, rows[2].Hash, 0, rows[1].Hash)
	require.False(t, movedFloor.Valid)
}

func TestAuditChainVerifierAcceptsFullyPrunedChain(t *testing.T) {
	rows := chainedEvents("", testAuditEvents()...)
	report := verifyRows(nil, 3, rows[2].Hash, 3, rows[2].Hash)
	require.True(t, report.Valid, report.Reason)
	require.Zero(t, report.Checked)

	broken := verifyRows(nil, 3, rows[2].Hash, 0, "")
	require.False(t, broken.Valid)
}

func TestAuditAnchorSignsAndVerifies(t *testing.T) {
	now := time.Now().UTC()
	signer := NewAuditAnchorer(AuditAnchorConfig{Secret: []byte("test-secret-with-enough-entropy")})
	require.NotNil(t, signer)

	anchor := signer.Sign(7, "abc123", now)
	require.EqualValues(t, 7, anchor.Seq)
	require.NotEmpty(t, anchor.PublicKey)
	require.NotEmpty(t, anchor.Signature)

	verifier := NewAuditAnchorVerifier(signer.PublicKey(), 1, 7)
	verifier.Add(anchor, "abc123")
	report := verifier.Finish()
	require.True(t, report.Valid, report.Reason)
	require.EqualValues(t, 1, report.Count)
	require.True(t, report.Enabled)
	require.NotEmpty(t, report.KeyFingerprint)
}

func TestAuditAnchorVerifierRejectsTampering(t *testing.T) {
	now := time.Now().UTC()
	signer := NewAuditAnchorer(AuditAnchorConfig{Secret: []byte("test-secret-with-enough-entropy")})
	anchor := signer.Sign(1, "abc123", now)

	tests := []struct {
		name   string
		mutate func(*AuditAnchor)
		hash   string
		reason string
	}{
		{"signature", func(a *AuditAnchor) { a.Signature = base64Signature(32) }, "abc123", "signature"},
		{"hash", func(a *AuditAnchor) { a.Hash = "different" }, "different", "signature"},
		{"chain hash", func(a *AuditAnchor) {}, "other", "does not match the audit chain"},
		{"public key", func(a *AuditAnchor) { a.PublicKey = base64Key() }, "abc123", "signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := anchor
			tc.mutate(&mutated)
			verifier := NewAuditAnchorVerifier(signer.PublicKey(), 1, 1)
			verifier.Add(mutated, tc.hash)
			require.False(t, verifier.Finish().Valid)
		})
	}
}

func TestAuditAnchorVerifierDetectsForeignKey(t *testing.T) {
	now := time.Now().UTC()
	signer := NewAuditAnchorer(AuditAnchorConfig{Secret: []byte("attacker-controlled-secret")})
	anchor := signer.Sign(1, "abc123", now)
	trusted := NewAuditAnchorer(AuditAnchorConfig{Secret: []byte("trusted-deployment-secret")})

	verifier := NewAuditAnchorVerifier(trusted.PublicKey(), 1, 1)
	verifier.Add(anchor, "abc123")
	report := verifier.Finish()
	require.False(t, report.Valid)
	require.Contains(t, report.Reason, "other than the configured audit key")
}

func TestAuditAnchorVerifierDetectsMissingAnchoredRow(t *testing.T) {
	now := time.Now().UTC()
	signer := NewAuditAnchorer(AuditAnchorConfig{Secret: []byte("test-secret-with-enough-entropy")})
	anchor := signer.Sign(3, "abc123", now)

	verifier := NewAuditAnchorVerifier(signer.PublicKey(), 1, 5)
	verifier.Add(anchor, "")
	require.False(t, verifier.Finish().Valid)
}

func base64Signature(size int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, size))
}

func base64Key() string {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}
