package ast

// Action represents the outcome decision of an AST verification.
type Action string

const (
	// ActionAllow permits the parameter candidate.
	ActionAllow Action = "allow"
	// ActionBlock flags verified injection breakout.
	ActionBlock Action = "block"
	// ActionAudit records telemetry (e.g. parser timeout) without blocking.
	ActionAudit Action = "audit"
)

// Verdict contains the AST decision and metadata.
type Verdict struct {
	Action Action `json:"action"`
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// VerdictAllow is a pre-allocated singleton for benign passthrough.
var VerdictAllow = &Verdict{
	Action: ActionAllow,
}
