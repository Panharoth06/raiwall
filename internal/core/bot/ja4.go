package bot

import (
	"context"
	"crypto/tls"
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

// ExtractJA4 returns the JA4 fingerprint captured from this connection's TLS
// handshake, as stored in the request context by the data plane. It never
// reads request headers: those are client-controlled unless the socket peer
// is a trusted proxy, and only the caller knows that (see JA4FromHeaders).
func ExtractJA4(r *http.Request) string {
	if r == nil {
		return ""
	}
	return GetJA4(r.Context())
}

// JA4FromHeaders reads a JA4 fingerprint forwarded by an edge proxy or CDN
// (X-JA4-Fingerprint, then JA4). Callers must only use it when the socket
// peer is a configured trusted proxy.
func JA4FromHeaders(h http.Header) string {
	if ja4 := strings.TrimSpace(h.Get(HeaderXJA4Fingerprint)); ja4 != "" {
		return ja4
	}
	return strings.TrimSpace(h.Get(HeaderJA4))
}
