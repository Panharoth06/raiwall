package caddy

import (
	"net"
	"net/http"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// maxConnUnwrapDepth bounds the NetConn() walk so a pathological wrapper
// chain cannot loop forever.
const maxConnUnwrapDepth = 8

// connFingerprints holds what the listener wrappers learned about one client
// connection. It lives on the connection, so it is released with it.
type connFingerprints struct {
	mu  sync.RWMutex
	ja4 string
	h2  *bot.HTTP2Fingerprint
}

func (c *connFingerprints) setJA4(v string) {
	c.mu.Lock()
	c.ja4 = v
	c.mu.Unlock()
}

func (c *connFingerprints) setH2(fp *bot.HTTP2Fingerprint) {
	c.mu.Lock()
	c.h2 = fp
	c.mu.Unlock()
}

func (c *connFingerprints) snapshot() (string, *bot.HTTP2Fingerprint) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ja4, c.h2
}

// fingerprintCarrier is implemented by the listener-wrapper connections that
// capture fingerprints.
type fingerprintCarrier interface {
	fingerprints() *connFingerprints
}

type netConnUnwrapper interface {
	NetConn() net.Conn
}

// connectionFingerprints finds the fingerprints captured for the connection
// that carried r, unwrapping TLS and other wrappers around it.
func connectionFingerprints(r *http.Request) (string, *bot.HTTP2Fingerprint) {
	conn, _ := r.Context().Value(caddyhttp.ConnCtxKey).(net.Conn)
	var ja4 string
	var h2 *bot.HTTP2Fingerprint
	for depth := 0; conn != nil && depth < maxConnUnwrapDepth; depth++ {
		if carrier, ok := conn.(fingerprintCarrier); ok {
			j, h := carrier.fingerprints().snapshot()
			if ja4 == "" {
				ja4 = j
			}
			if h2 == nil {
				h2 = h
			}
		}
		u, ok := conn.(netConnUnwrapper)
		if !ok {
			break
		}
		conn = u.NetConn()
	}
	return ja4, h2
}

// peerIsTrustedProxy reports whether the socket peer is inside the
// application's trusted_proxies. With no trusted proxies configured no peer is
// trusted, so forwarded fingerprint headers are ignored.
func peerIsTrustedProxy(r *http.Request, trustedProxies []string) bool {
	trusted := parseTrustedPrefixes(trustedProxies)
	if len(trusted) == 0 {
		return false
	}
	return ipInPrefixes(parseRemoteAddr(r.RemoteAddr), trusted)
}

// resolveFingerprints returns the JA4 and HTTP/2 fingerprints for r. Values
// captured from the connection always win. Forwarded headers are only used
// when the socket peer is a configured trusted proxy.
func resolveFingerprints(r *http.Request, trustedProxies []string) (string, *bot.HTTP2Fingerprint) {
	ja4, h2 := connectionFingerprints(r)
	// Values already in the request context were set server-side (an earlier
	// stage or the embedding code), never by the client.
	if ja4 == "" {
		ja4 = bot.ExtractJA4(r)
	}
	if h2 == nil {
		h2 = bot.ExtractHTTP2Fingerprint(r)
	}
	if ja4 != "" && h2 != nil {
		return ja4, h2
	}
	if peerIsTrustedProxy(r, trustedProxies) {
		if ja4 == "" {
			ja4 = bot.JA4FromHeaders(r.Header)
		}
		if h2 == nil {
			h2 = bot.HTTP2FingerprintFromHeaders(r.Header)
		}
	}
	return ja4, h2
}
