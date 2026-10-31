package caddy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type contextKey string

const clientIPContextKey contextKey = "raiwall.client_ip"

// ExtractClientIP returns the direct socket peer. Forwarded headers are only
// honored when the application explicitly configures a source, so a client
// cannot spoof its address (and therefore its geo, ACL, rate-limit, and ban
// keys) by sending CF-Connecting-IP/X-Real-IP/X-Forwarded-For.
func ExtractClientIP(r *http.Request) net.IP {
	return ExtractClientIPWithSource(r, "")
}

// ExtractClientIPWithSource extracts the client IP using a configured source:
//
//	"" / "socket" / "remoteaddr" / "remote" -> socket RemoteAddr only
//	"header" / "xff" / "x-forwarded-for"     -> X-Forwarded-For
//	"x-real-ip" / "cf-connecting-ip"        -> that header
//	any other value                          -> treated as a header name
//
// Header-based sources trust the forwarding chain. Operators behind a proxy
// must opt in explicitly; use ExtractClientIPWithTrustedProxies to restrict
// which peers may assert the header.
func ExtractClientIPWithSource(r *http.Request, source string) net.IP {
	return ExtractClientIPWithTrustedProxies(r, source, nil)
}

// ExtractClientIPWithTrustedProxies resolves the client IP with a trusted-proxy
// allowlist. When the direct peer is not trusted, forwarded headers are ignored
// entirely. When it is trusted, X-Forwarded-For is walked right-to-left,
// skipping trusted hops, so the first untrusted address is the client.
func ExtractClientIPWithTrustedProxies(r *http.Request, source string, trustedProxies []string) net.IP {
	if r == nil {
		return nil
	}

	socketIP := parseRemoteAddr(r.RemoteAddr)
	src := strings.ToLower(strings.TrimSpace(source))

	var headerName string
	switch src {
	case "", "socket", "remoteaddr", "remote":
		return socketIP
	case "header", "xff", "x-forwarded-for":
		headerName = "X-Forwarded-For"
	case "x-real-ip":
		headerName = "X-Real-IP"
	case "cf-connecting-ip":
		headerName = "CF-Connecting-IP"
	default:
		headerName = source
	}

	trusted := parseTrustedPrefixes(trustedProxies)
	if len(trusted) > 0 && !ipInPrefixes(socketIP, trusted) {
		// The immediate peer may not assert a client address.
		return socketIP
	}

	if strings.EqualFold(headerName, "X-Forwarded-For") {
		return forwardedClientIP(r.Header.Get(headerName), socketIP, trusted)
	}
	if val := strings.TrimSpace(r.Header.Get(headerName)); val != "" {
		if ip := parseValidIP(val); ip != nil {
			return ip
		}
	}
	return socketIP
}

// forwardedClientIP selects the client address from an XFF chain.
//
// With no trusted proxies, the legacy left-most behavior applies (the operator
// opted into header trust). With trusted proxies, walk right-to-left and skip
// hops that are trusted; the first untrusted hop is the client.
func forwardedClientIP(xff string, socketIP net.IP, trusted []netip.Prefix) net.IP {
	var parts []net.IP
	for _, part := range strings.Split(xff, ",") {
		if ip := parseValidIP(part); ip != nil {
			parts = append(parts, ip)
		}
	}
	if len(parts) == 0 {
		return socketIP
	}
	if len(trusted) == 0 {
		return parts[0]
	}

	chain := append(parts, socketIP)
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i] == nil || ipInPrefixes(chain[i], trusted) {
			continue
		}
		return chain[i]
	}
	return parts[0]
}

func parseTrustedPrefixes(raw []string) []netip.Prefix {
	if len(raw) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			out = append(out, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out
}

func ipInPrefixes(ip net.IP, prefixes []netip.Prefix) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// WithClientIP injects the extracted client net.IP into context.
func WithClientIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, clientIPContextKey, ip)
}

// GetClientIP retrieves the client IP from request context, falling back to ExtractClientIP.
func GetClientIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if val := r.Context().Value(clientIPContextKey); val != nil {
		if ip, ok := val.(net.IP); ok && ip != nil {
			return ip
		}
	}
	return ExtractClientIP(r)
}

func parseValidIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// If it contains host:port (e.g. "[2001:db8::1]:8080" or "192.0.2.1:8080"), split it first
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	// Strip square brackets if IPv6 literal like "[2001:db8::1]"
	raw = strings.Trim(raw, "[]")
	return net.ParseIP(raw)
}

func parseRemoteAddr(remoteAddr string) net.IP {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return nil
	}
	return parseValidIP(remoteAddr)
}
