package waf

// WAFEnginePort defines the primary port contract for threat inspection engines.
type WAFEnginePort interface {
	// InspectRequest inspects an inbound HTTP request prior to upstream forwarding.
	InspectRequest(ctx *RequestContext) (*Verdict, error)
	// InspectResponse inspects the upstream HTTP response prior to returning to client.
	InspectResponse(ctx *ResponseContext) (*Verdict, error)
	// Name returns the identifier of the engine implementation.
	Name() string
}

// WAFEngine is an alias for WAFEnginePort for backward compatibility.
type WAFEngine = WAFEnginePort

// NormalizerPort defines the contract for recursive normalization engines.
type NormalizerPort interface {
	Normalize(input string) string
}

// ExceptionMatcher determines if a parameter matches an active false-positive bypass rule.
type ExceptionMatcher interface {
	Matches(host, path, method, location, paramName, ruleID string) bool
}
