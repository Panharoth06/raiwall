package engine

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPassthroughEngine(t *testing.T) {
	eng := NewPassthroughEngine()
	if eng.Name() != "passthrough" {
		t.Errorf("expected engine name 'passthrough', got %q", eng.Name())
	}

	reqCtx := &RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Method:   "GET",
		Host:     "example.com",
		Path:     "/",
		Headers:  make(http.Header),
	}

	verdict, err := eng.InspectRequest(reqCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %v", verdict.Action)
	}

	respCtx := &ResponseContext{
		StatusCode: 200,
		Headers:    make(http.Header),
		Duration:   5 * time.Millisecond,
	}

	verdict, err = eng.InspectResponse(respCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %v", verdict.Action)
	}
}

func BenchmarkPassthroughEngine(b *testing.B) {
	eng := NewPassthroughEngine()
	reqCtx := &RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Method:   "GET",
		Host:     "example.com",
		Path:     "/test",
		Headers:  make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.InspectRequest(reqCtx)
	}
}

func TestMockEngine(t *testing.T) {
	mock := NewMockEngine()

	// Default behavior
	reqCtx := &RequestContext{Path: "/test"}
	verdict, err := mock.InspectRequest(reqCtx)
	if err != nil || verdict.Action != ActionAllow {
		t.Fatalf("default should allow, got %v, err %v", verdict, err)
	}

	// Custom block behavior
	mock.InspectRequestHandler = func(ctx *RequestContext) (*Verdict, error) {
		if ctx.Path == "/blocked" {
			return &Verdict{
				Action:     ActionBlock,
				RuleID:     "BLOCK_RULE_1",
				Reason:     "Suspicious URI",
				StatusCode: 403,
			}, nil
		}
		return VerdictAllow, nil
	}

	verdict, err = mock.InspectRequest(&RequestContext{Path: "/blocked"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != ActionBlock || verdict.RuleID != "BLOCK_RULE_1" {
		t.Errorf("expected block verdict, got %v", verdict)
	}

	// Error path
	expectedErr := errors.New("engine error")
	mock.InspectRequestHandler = func(ctx *RequestContext) (*Verdict, error) {
		return nil, expectedErr
	}

	_, err = mock.InspectRequest(&RequestContext{Path: "/err"})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}
