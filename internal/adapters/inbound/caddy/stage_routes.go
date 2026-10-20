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
	// Internal WAF routes: Metrics & Telemetry API
	if r.URL.Path == "/.raiwall/metrics" ||
		r.URL.Path == "/.raiwall/api/events" ||
		r.URL.Path == "/.raiwall/api/events/stats" ||
		r.URL.Path == "/.raiwall/api/events/stream" {
		if m.telemetryAPI != nil {
			m.telemetryAPI.ServeHTTP(w, r)
			return true
		}
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
