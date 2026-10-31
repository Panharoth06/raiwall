package waf

// CompositeEngine runs a fast primary engine (the semantic funnel) and a
// secondary engine (OWASP CRS) over the same request. A block from either
// wins; otherwise the first audit verdict is surfaced so operators see what
// would have blocked.
type CompositeEngine struct {
	primary   WAFEnginePort
	secondary WAFEnginePort
}

// NewCompositeEngine builds a composite from two engines. Nil engines are
// skipped, so callers can compose conditionally.
func NewCompositeEngine(primary, secondary WAFEnginePort) *CompositeEngine {
	return &CompositeEngine{primary: primary, secondary: secondary}
}

// Name returns the identifier for this engine.
func (c *CompositeEngine) Name() string {
	return "composite"
}

// InspectRequest evaluates both engines in order.
func (c *CompositeEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	var audit *Verdict

	if c.primary != nil {
		v, err := c.primary.InspectRequest(ctx)
		if err != nil {
			return nil, err
		}
		if v != nil && v.Action == ActionBlock {
			return v, nil
		}
		if v != nil && v.Action == ActionAudit {
			audit = v
		}
	}

	if c.secondary != nil {
		v, err := c.secondary.InspectRequest(ctx)
		if err != nil {
			return nil, err
		}
		if v != nil && v.Action == ActionBlock {
			return v, nil
		}
		if v != nil && v.Action == ActionAudit && audit == nil {
			audit = v
		}
	}

	if audit != nil {
		return audit, nil
	}
	return VerdictAllow, nil
}

// InspectResponse evaluates both engines in order; a block wins.
func (c *CompositeEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	var audit *Verdict

	for _, engine := range []WAFEnginePort{c.primary, c.secondary} {
		if engine == nil {
			continue
		}
		v, err := engine.InspectResponse(ctx)
		if err != nil {
			return nil, err
		}
		if v != nil && v.Action == ActionBlock {
			return v, nil
		}
		if v != nil && v.Action == ActionAudit && audit == nil {
			audit = v
		}
	}

	if audit != nil {
		return audit, nil
	}
	return VerdictAllow, nil
}
