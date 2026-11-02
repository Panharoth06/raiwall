package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// DefaultAuditAnchorInterval anchors every N audit events.
	DefaultAuditAnchorInterval int64 = 100
	// DefaultAuditAnchorMaxAge anchors at least this often even when the event
	// rate is low, so a quiet system still produces fresh anchors.
	DefaultAuditAnchorMaxAge = time.Hour
)

// AuditAnchor is a signed checkpoint over the hash chain. Anchors let an
// operator verify the chain head out of band: an attacker who can rewrite the
// database still cannot produce a valid signature for a rewritten head.
type AuditAnchor struct {
	Seq       int64     `json:"seq"`
	Hash      string    `json:"hash"`
	SignedAt  time.Time `json:"signed_at"`
	PublicKey string    `json:"public_key"`
	Signature string    `json:"signature"`
}

// AuditAnchorConfig configures checkpoint signing. Secret is the deployment
// secret the Ed25519 key is derived from; it must stay stable for anchors to
// remain verifiable across restarts.
type AuditAnchorConfig struct {
	Secret   []byte
	Interval int64
	MaxAge   time.Duration
}

// AuditAnchorConfigurer is implemented by stores that can sign checkpoints.
type AuditAnchorConfigurer interface {
	ConfigureAuditAnchoring(AuditAnchorConfig)
}

// ConfigureAuditAnchoring enables checkpoint signing on a store when it
// supports it. Stores without the capability keep the unsigned hash chain.
func ConfigureAuditAnchoring(store ControlStore, cfg AuditAnchorConfig) {
	if configurer, ok := store.(AuditAnchorConfigurer); ok {
		configurer.ConfigureAuditAnchoring(cfg)
	}
}

// AuditAnchorMessage returns the canonical bytes covered by a signature.
// Values are length-delimited and the timestamp is fixed to microsecond
// precision so the message is identical before storage and after a round-trip.
func AuditAnchorMessage(seq int64, hash string, signedAt time.Time) []byte {
	stamp := signedAt.UTC().Truncate(AuditTimePrecision).Format(time.RFC3339Nano)
	return []byte(fmt.Sprintf("raiwall-audit-anchor-v1|%d|%d:%s|%s", seq, len(hash), hash, stamp))
}

// AuditAnchorKey derives the deterministic Ed25519 key used for checkpoints.
// Deriving from the deployment secret avoids a second mandatory secret while
// keeping the private key out of the database.
func AuditAnchorKey(secret []byte) ed25519.PrivateKey {
	h := sha256.New()
	h.Write([]byte("raiwall/audit-anchor/v1\x00"))
	h.Write(secret)
	return ed25519.NewKeyFromSeed(h.Sum(nil))
}

// AuditAnchorFingerprint identifies a public key without exposing it in logs.
func AuditAnchorFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// AuditAnchorer signs checkpoints at the configured interval.
type AuditAnchorer struct {
	key      ed25519.PrivateKey
	interval int64
	maxAge   time.Duration
}

// NewAuditAnchorer builds a signer. A nil result disables anchoring.
func NewAuditAnchorer(cfg AuditAnchorConfig) *AuditAnchorer {
	if len(cfg.Secret) == 0 {
		return nil
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultAuditAnchorInterval
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultAuditAnchorMaxAge
	}
	return &AuditAnchorer{key: AuditAnchorKey(cfg.Secret), interval: interval, maxAge: maxAge}
}

// ShouldAnchor reports whether the next event should be checkpointed: every N
// events, when T has elapsed since the last anchor, or on the first event.
func (a *AuditAnchorer) ShouldAnchor(seq int64, now, lastSignedAt time.Time, hasLast bool) bool {
	if a == nil {
		return false
	}
	if a.interval > 0 && seq%a.interval == 0 {
		return true
	}
	if !hasLast {
		return true
	}
	return a.maxAge > 0 && now.Sub(lastSignedAt) >= a.maxAge
}

// Sign creates a checkpoint for the given chain position.
func (a *AuditAnchorer) Sign(seq int64, hash string, now time.Time) AuditAnchor {
	signedAt := now.UTC().Truncate(AuditTimePrecision)
	sig := ed25519.Sign(a.key, AuditAnchorMessage(seq, hash, signedAt))
	return AuditAnchor{
		Seq:       seq,
		Hash:      hash,
		SignedAt:  signedAt,
		PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

// PublicKey exposes the verification key for the verify API.
func (a *AuditAnchorer) PublicKey() ed25519.PublicKey {
	if a == nil {
		return nil
	}
	return a.key.Public().(ed25519.PublicKey)
}

// AuditAnchorReport summarizes checkpoint verification.
type AuditAnchorReport struct {
	Enabled        bool   `json:"enabled"`
	Count          int64  `json:"count"`
	Checked        int64  `json:"checked"`
	Valid          bool   `json:"valid"`
	CurrentKey     string `json:"current_key,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	BrokenAtSeq    int64  `json:"broken_at_seq,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// AuditAnchorVerifier checks each anchor's signature, its key, and (when the
// chain row still exists) the anchored hash. Anchors before the retained chain
// prefix are valid as long as their signatures verify.
type AuditAnchorVerifier struct {
	report   AuditAnchorReport
	current  ed25519.PublicKey
	firstSeq int64
	lastSeq  int64
	failed   bool
	keys     map[string]bool
}

// NewAuditAnchorVerifier starts a verification pass over a retained chain
// window [firstSeq, lastSeq]. Zero bounds mean the chain is empty.
func NewAuditAnchorVerifier(current ed25519.PublicKey, firstSeq, lastSeq int64) *AuditAnchorVerifier {
	report := AuditAnchorReport{Enabled: len(current) > 0, Valid: true}
	if len(current) > 0 {
		report.CurrentKey = base64.StdEncoding.EncodeToString(current)
		report.KeyFingerprint = AuditAnchorFingerprint(current)
	}
	return &AuditAnchorVerifier{
		report:   report,
		current:  current,
		firstSeq: firstSeq,
		lastSeq:  lastSeq,
		keys:     make(map[string]bool),
	}
}

func (v *AuditAnchorVerifier) fail(anchor AuditAnchor, reason string) {
	v.failed = true
	v.report.BrokenAtSeq = anchor.Seq
	v.report.Reason = reason
}

// Add validates one anchor. chainHash is empty when the anchored chain row has
// already been removed by retention.
func (v *AuditAnchorVerifier) Add(anchor AuditAnchor, chainHash string) {
	v.report.Count++
	v.report.Checked++
	v.keys[anchor.PublicKey] = true
	if v.failed {
		return
	}

	pubRaw, err := base64.StdEncoding.DecodeString(anchor.PublicKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		v.fail(anchor, "anchor public key is malformed")
		return
	}
	pub := ed25519.PublicKey(pubRaw)
	sig, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		v.fail(anchor, "anchor signature is malformed")
		return
	}
	if !ed25519.Verify(pub, AuditAnchorMessage(anchor.Seq, anchor.Hash, anchor.SignedAt), sig) {
		v.fail(anchor, "anchor signature does not verify")
		return
	}
	if len(v.current) > 0 && !v.current.Equal(pub) {
		v.fail(anchor, "anchor was signed by a key other than the configured audit key")
		return
	}
	if chainHash != "" && chainHash != anchor.Hash {
		v.fail(anchor, "anchored hash does not match the audit chain")
		return
	}
	if chainHash == "" && v.lastSeq > 0 && anchor.Seq >= v.firstSeq && anchor.Seq <= v.lastSeq {
		v.fail(anchor, "anchored chain row is missing")
	}
}

// Finish returns the accumulated report. Extra keys are reported so a silent
// key substitution is visible even to an operator without the chain window.
func (v *AuditAnchorVerifier) Finish() AuditAnchorReport {
	if !v.failed && v.report.Count > 1 && len(v.keys) > 1 {
		v.report.Valid = false
		v.report.Reason = "anchors were signed by more than one key"
		return v.report
	}
	v.report.Valid = !v.failed
	return v.report
}
