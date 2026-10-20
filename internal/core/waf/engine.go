package waf

// PassthroughEngine is a no-op WAFEngine implementation with zero allocations and sub-microsecond overhead.
type PassthroughEngine struct{}

// NewPassthroughEngine creates a thread-safe passthrough engine.
func NewPassthroughEngine() *PassthroughEngine {
	return &PassthroughEngine{}
}

// InspectRequest allows any request without inspection.
func (p *PassthroughEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	return VerdictAllow, nil
}

// InspectResponse allows any response without modification.
func (p *PassthroughEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	return VerdictAllow, nil
}

// Name returns the name of the engine.
func (p *PassthroughEngine) Name() string {
	return "passthrough"
}

// MockEngine is a test double enabling custom request and response inspection handlers.
type MockEngine struct {
	EngineName             string
	InspectRequestHandler  func(ctx *RequestContext) (*Verdict, error)
	InspectResponseHandler func(ctx *ResponseContext) (*Verdict, error)
}

// NewMockEngine creates a new configurable MockEngine for testing.
func NewMockEngine() *MockEngine {
	return &MockEngine{
		EngineName: "mock",
		InspectRequestHandler: func(ctx *RequestContext) (*Verdict, error) {
			return VerdictAllow, nil
		},
		InspectResponseHandler: func(ctx *ResponseContext) (*Verdict, error) {
			return VerdictAllow, nil
		},
	}
}

// InspectRequest delegates to the configured handler.
func (m *MockEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	if m.InspectRequestHandler != nil {
		return m.InspectRequestHandler(ctx)
	}
	return VerdictAllow, nil
}

// InspectResponse delegates to the configured handler.
func (m *MockEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	if m.InspectResponseHandler != nil {
		return m.InspectResponseHandler(ctx)
	}
	return VerdictAllow, nil
}

// Name returns the identifier of the mock engine.
func (m *MockEngine) Name() string {
	if m.EngineName != "" {
		return m.EngineName
	}
	return "mock"
}
