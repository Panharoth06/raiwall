package control

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// AuditTimePrecision is the resolution at which audit timestamps are hashed and
// stored. PostgreSQL keeps microseconds, so anything finer would never verify.
const AuditTimePrecision = time.Microsecond

// AuditEventHash links an audit event to its predecessor. Every field is
// length-prefixed so adjacent values cannot be shifted into one another.
func AuditEventHash(prevHash string, e AuditEvent) string {
	h := sha256.New()
	write := func(v string) { fmt.Fprintf(h, "%d:%s|", len(v), v) }
	write(prevHash)
	write(e.ID)
	write(e.OccurredAt.UTC().Format(time.RFC3339Nano))
	write(e.ActorType)
	write(e.ActorID)
	write(e.ActorName)
	write(e.Role)
	write(e.Action)
	write(e.TargetType)
	write(e.TargetID)
	write(e.Method)
	write(e.Path)
	write(strconv.Itoa(e.StatusCode))
	write(e.RequestID)
	write(e.ClientIP)
	write(e.UserAgent)
	write(strconv.FormatUint(e.SnapshotVersion, 10))
	write(e.Detail)
	return hex.EncodeToString(h.Sum(nil))
}

// AuditChainRow is one stored audit event with its chain linkage.
type AuditChainRow struct {
	Event    AuditEvent
	Seq      int64
	PrevHash string
	Hash     string
}

// AuditChainReport is the result of verifying the audit hash chain.
type AuditChainReport struct {
	Valid bool `json:"valid"`
	// Checked is the number of chained events examined.
	Checked int64 `json:"checked"`
	// Unchained counts events stored without chain linkage: records written
	// before the chain existed, or whose chain row was removed.
	Unchained     int64  `json:"unchained"`
	FirstSeq      int64  `json:"first_seq,omitempty"`
	LastSeq       int64  `json:"last_seq,omitempty"`
	BrokenAtSeq   int64  `json:"broken_at_seq,omitempty"`
	BrokenEventID string `json:"broken_event_id,omitempty"`
	Reason        string `json:"reason,omitempty"`
	// Anchors reports Ed25519 checkpoint verification.
	Anchors AuditAnchorReport `json:"anchors"`
}

// AuditChainVerifier checks rows streamed in ascending sequence order. The
// first row's PrevHash is accepted as the anchor, because retention pruning
// legitimately removes the oldest links.
type AuditChainVerifier struct {
	report    AuditChainReport
	lastHash  string
	firstPrev string
	started   bool
	failed    bool
}

// NewAuditChainVerifier starts a verification pass.
func NewAuditChainVerifier(unchained int64) *AuditChainVerifier {
	return &AuditChainVerifier{report: AuditChainReport{Unchained: unchained}}
}

func (v *AuditChainVerifier) fail(row AuditChainRow, reason string) {
	v.failed = true
	v.report.BrokenAtSeq = row.Seq
	v.report.BrokenEventID = row.Event.ID
	v.report.Reason = reason
}

// Add examines the next row. Rows after the first failure are ignored so the
// report points at the earliest break.
func (v *AuditChainVerifier) Add(row AuditChainRow) {
	if v.failed {
		return
	}
	if v.started {
		if row.Seq != v.report.LastSeq+1 {
			v.fail(row, fmt.Sprintf("sequence gap: expected %d, found %d (event removed)", v.report.LastSeq+1, row.Seq))
			return
		}
		if row.PrevHash != v.lastHash {
			v.fail(row, "previous hash does not match the preceding event")
			return
		}
	} else {
		v.report.FirstSeq = row.Seq
		v.firstPrev = row.PrevHash
		v.started = true
	}
	if AuditEventHash(row.PrevHash, row.Event) != row.Hash {
		v.fail(row, "event contents do not match the recorded hash (event modified)")
		return
	}
	v.lastHash = row.Hash
	v.report.LastSeq = row.Seq
	v.report.Checked++
}

// Finish compares the retained window with the recorded floor and head. The
// floor is the last sequence removed by retention; the first retained row must
// link to it, and the last retained row must match the head. This catches both
// events removed from the middle and events truncated from the end.
func (v *AuditChainVerifier) Finish(headSeq int64, headHash string, floorSeq int64, floorHash string) AuditChainReport {
	if !v.failed {
		switch {
		case !v.started && (headSeq != floorSeq || headHash != floorHash):
			v.report.BrokenAtSeq = headSeq
			v.report.Reason = "chain rows are missing but the head records events"
			v.failed = true
		case v.started && (v.report.FirstSeq != floorSeq+1 || v.firstPrev != floorHash):
			v.report.BrokenAtSeq = v.report.FirstSeq
			v.report.Reason = "first retained event does not link to the recorded retention floor"
			v.failed = true
		case v.started && (v.report.LastSeq != headSeq || v.lastHash != headHash):
			v.report.BrokenAtSeq = v.report.LastSeq
			v.report.Reason = "chain tail does not match the head record (trailing events removed)"
			v.failed = true
		}
	}
	v.report.Valid = !v.failed
	return v.report
}
