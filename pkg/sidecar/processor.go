package sidecar

import (
	"context"
	"net"
	"net/http"

	"github.com/Panharoth06/raiwall/pkg/engine"
)

// RequestProcessor encapsulates sidecar request inspection logic.
type RequestProcessor struct {
	engine      engine.WAFEngine
	maxBodySize int
}

// NewRequestProcessor creates a new RequestProcessor.
func NewRequestProcessor(wafEngine engine.WAFEngine, maxBodySize int) *RequestProcessor {
	if maxBodySize <= 0 {
		maxBodySize = DefaultMaxBodySize
	}
	if wafEngine == nil {
		wafEngine = engine.NewSemanticEngine()
	}
	return &RequestProcessor{
		engine:      wafEngine,
		maxBodySize: maxBodySize,
	}
}

// Inspect inspects the assembled request. If body exceeds maxBodySize, inspection of body is skipped.
func (p *RequestProcessor) Inspect(ctx context.Context, clientIP net.IP, method, host, path string, headers http.Header, body []byte) (*engine.Verdict, error) {
	reqCtx := &engine.RequestContext{
		ClientIP: clientIP,
		Method:   method,
		Host:     host,
		Path:     path,
		Headers:  headers,
		Body:     body,
		Context:  ctx,
	}

	return p.engine.InspectRequest(reqCtx)
}
