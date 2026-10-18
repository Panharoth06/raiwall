package bot

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/exaring/ja4plus"
)

// Header constants for JA4 extraction from upstream reverse proxies or CDNs.
const (
	HeaderXJA4Fingerprint = "X-JA4-Fingerprint"
	HeaderJA4             = "JA4"
)

type contextKey string

const ja4ContextKey contextKey = "raiwall.bot.ja4"

// WithJA4 returns a child context carrying the JA4 fingerprint string.
func WithJA4(ctx context.Context, ja4 string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ja4ContextKey, ja4)
}

// GetJA4 retrieves the JA4 fingerprint string from context if set.
func GetJA4(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(ja4ContextKey).(string); ok {
		return v
	}
	// Fall back to ja4plus context extraction if present
	return ja4plus.JA4FromContext(ctx)
}

// ComputeJA4 extracts the JA4 TLS client fingerprint from tls.ClientHelloInfo.
// Returns an empty string if hello is nil.
func ComputeJA4(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	return ja4plus.JA4(hello)
}

// ExtractJA4 extracts the JA4 fingerprint from the request context,
// or falls back to trusted upstream headers (X-JA4-Fingerprint, JA4).
func ExtractJA4(r *http.Request) string {
	if r == nil {
		return ""
	}

	// 1. Check request context first
	if ja4 := GetJA4(r.Context()); ja4 != "" {
		return ja4
	}

	// 2. Upstream header fallback: X-JA4-Fingerprint
	if ja4 := strings.TrimSpace(r.Header.Get(HeaderXJA4Fingerprint)); ja4 != "" {
		return ja4
	}

	// 3. Upstream header fallback: JA4
	if ja4 := strings.TrimSpace(r.Header.Get(HeaderJA4)); ja4 != "" {
		return ja4
	}

	return ""
}

// DirectTLSCapturer captures JA4 fingerprints during direct TLS handshakes
// using ja4plus.JA4Middleware for listener/server integration.
type DirectTLSCapturer struct {
	middleware ja4plus.JA4Middleware
}

// NewDirectTLSCapturer constructs an initialized DirectTLSCapturer.
func NewDirectTLSCapturer() *DirectTLSCapturer {
	return &DirectTLSCapturer{}
}

// GetConfigForClient can be plugged into tls.Config.GetConfigForClient to capture
// client TLS ClientHello fingerprints during the handshake.
func (c *DirectTLSCapturer) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello != nil && hello.Conn != nil {
		c.middleware.StoreFingerprintFromClientHello(hello)
	}
	return nil, nil
}

// ConnStateCallback can be registered with http.Server.ConnState to associate
// connections with captured fingerprints.
func (c *DirectTLSCapturer) ConnStateCallback(conn net.Conn, state http.ConnState) {
	c.middleware.ConnStateCallback(conn, state)
}

// Wrap wraps an http.Handler to automatically inject the captured JA4 fingerprint
// into the incoming request context.
func (c *DirectTLSCapturer) Wrap(next http.Handler) http.Handler {
	return c.middleware.Wrap(next)
}
