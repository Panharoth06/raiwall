package proxy

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type contextKey string

const clientIPContextKey contextKey = "raiwall.client_ip"

// ExtractClientIP determines the real client IP using priority-based header extraction:
// 1. CF-Connecting-IP (Cloudflare)
// 2. X-Real-IP (Nginx / standard proxies)
// 3. X-Forwarded-For (left-most client IP in chain)
// 4. RemoteAddr (direct socket connection)
func ExtractClientIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}

	// 1. Cloudflare header
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if ip := parseValidIP(cfIP); ip != nil {
			return ip
		}
	}

	// 2. X-Real-IP header
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if ip := parseValidIP(realIP); ip != nil {
			return ip
		}
	}

	// 3. X-Forwarded-For (first valid IP in comma-separated list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			clean := strings.TrimSpace(part)
			if clean == "" {
				continue
			}
			if ip := parseValidIP(clean); ip != nil {
				return ip
			}
		}
	}

	// 4. Fallback to RemoteAddr
	return parseRemoteAddr(r.RemoteAddr)
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
