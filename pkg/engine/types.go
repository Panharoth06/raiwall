package engine

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Action represents the outcome decision of a WAF inspection.
type Action string

const (
	// ActionAllow permits the request or response to proceed.
	ActionAllow Action = "allow"
	// ActionBlock immediately halts processing and serves a block response.
	ActionBlock Action = "block"
	// ActionChallenge serves a challenge (e.g. CAPTCHA / JS challenge).
	ActionChallenge Action = "challenge"
	// ActionAudit records telemetry without interrupting traffic flow.
	ActionAudit Action = "audit"
)

// Verdict contains the inspection decision and metadata.
type Verdict struct {
	Action     Action  `json:"action"`
	RuleID     string  `json:"rule_id,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	StatusCode int     `json:"status_code,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// VerdictAllow is a pre-allocated singleton for clean zero-allocation passthrough.
var VerdictAllow = &Verdict{
	Action: ActionAllow,
}

// RequestContext encapsulates all incoming HTTP request attributes for inspection.
type RequestContext struct {
	ClientIP   net.IP          `json:"client_ip"`
	Method     string          `json:"method"`
	Host       string          `json:"host"`
	Path       string          `json:"path"`
	Query      string          `json:"query"`
	Headers    http.Header     `json:"headers"`
	Body       []byte          `json:"body,omitempty"`
	TLSVersion uint16          `json:"tls_version,omitempty"`
	UserAgent  string          `json:"user_agent,omitempty"`
	AppID      string          `json:"app_id,omitempty"`
	Context    context.Context `json:"-"`
}

// ResponseContext encapsulates upstream response attributes for inspection.
type ResponseContext struct {
	StatusCode int             `json:"status_code"`
	Headers    http.Header     `json:"headers"`
	Body       []byte          `json:"body,omitempty"`
	Duration   time.Duration   `json:"duration"`
	Context    context.Context `json:"-"`
}

// WAFEngine defines the abstract contract for threat inspection engines.
type WAFEngine interface {
	// InspectRequest inspects an inbound HTTP request prior to upstream forwarding.
	InspectRequest(ctx *RequestContext) (*Verdict, error)
	// InspectResponse inspects the upstream HTTP response prior to returning to client.
	InspectResponse(ctx *ResponseContext) (*Verdict, error)
	// Name returns the identifier of the engine implementation.
	Name() string
}
