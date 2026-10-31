package caddy

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// parseAdminNetworks compiles control.allowed_networks. An empty list means
// unrestricted, preserving compatibility for existing deployments.
func parseAdminNetworks(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid control.allowed_networks %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// isInternalAdminPath reports whether the path is served by the control plane,
// dashboard, metrics, or telemetry rather than proxied to an upstream.
func isInternalAdminPath(path string) bool {
	if path == "/.raiwall" || strings.HasPrefix(path, "/.raiwall/") {
		return true
	}
	return isTelemetryPath(path) || isGeoIPStatusPath(path)
}

// adminClientAllowed enforces control.allowed_networks. The socket peer is used
// deliberately: forwarded headers are not trusted for the admin surface.
func (m *Middleware) adminClientAllowed(r *http.Request) bool {
	if len(m.adminNetworks) == 0 {
		return true
	}
	ip := ExtractClientIP(r)
	if ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range m.adminNetworks {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
