package caddy

import (
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/rate"
)

// serveInternalRoutes intercepts requests to Raiwall internal endpoints (telemetry, API, UI).
// Returns true if the request was handled internally and requires no further processing.
func (m *Middleware) serveInternalRoutes(w http.ResponseWriter, r *http.Request) bool {
	// Internal WAF routes: GeoIP database status for the dashboard
	if m.geoipAPI != nil && isGeoIPStatusPath(r.URL.Path) {
		m.geoipAPI.ServeHTTP(w, r)
		return true
	}

	// Internal WAF routes: Metrics & Telemetry API
	if m.telemetryAPI != nil && isTelemetryPath(r.URL.Path) {
		m.telemetryAPI.ServeHTTP(w, r)
		return true
	}

	// Internal WAF routes: Control Plane REST API, OpenAPI Docs & MCP
	if m.controlAPI != nil && strings.HasPrefix(r.URL.Path, "/.raiwall/api/") {
		m.controlAPI.ServeHTTP(w, r)
		return true
	}

	// Internal WAF routes: Embedded UI Admin Dashboard
	if (r.URL.Path == "/.raiwall" || strings.HasPrefix(r.URL.Path, "/.raiwall/")) &&
		r.URL.Path != rate.WaitingRoomEventsPath &&
		!bot.IsTrapRequest(r.URL.Path) &&
		r.URL.Path != bot.ChallengeVerifyPath &&
		!strings.HasPrefix(r.URL.Path, "/.raiwall/auth") {
		if m.uiHandler != nil {
			m.uiHandler.ServeHTTP(w, r)
			return true
		}
	}

	return false
}

// isGeoIPStatusPath reports whether a request targets the GeoIP status endpoint.
func isGeoIPStatusPath(p string) bool {
	switch strings.TrimSuffix(p, "/") {
	case "/.raiwall/api/telemetry/geoip",
		"/api/v1/telemetry/geoip",
		"/.raiwall/api/v1/telemetry/geoip":
		return true
	}
	return false
}

// isTelemetryPath reports whether a request targets the telemetry/metrics API surface.
func isTelemetryPath(p string) bool {
	switch p {
	case "/.raiwall/metrics", "/metrics",
		"/.raiwall/api/events", "/api/v1/telemetry/events", "/.raiwall/api/v1/telemetry/events",
		"/.raiwall/api/events/stats", "/api/v1/telemetry/events/stats", "/.raiwall/api/v1/telemetry/events/stats",
		"/.raiwall/api/events/stream", "/api/v1/telemetry/events/stream", "/.raiwall/api/v1/telemetry/events/stream",
		"/.raiwall/api/incidents", "/api/v1/telemetry/incidents", "/.raiwall/api/v1/telemetry/incidents":
		return true
	}
	if !strings.HasSuffix(p, "/curl") {
		return false
	}
	return strings.HasPrefix(p, "/.raiwall/api/events/") ||
		strings.HasPrefix(p, "/api/v1/telemetry/events/") ||
		strings.HasPrefix(p, "/.raiwall/api/v1/telemetry/events/")
}
