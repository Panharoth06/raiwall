package caddy

import (
	"net/http"
	"path"
	"strings"
)

// adminDashboardPath is the reserved control-plane namespace that serves the
// embedded dashboard (see stage_routes.go).
const adminDashboardPath = "/.raiwall/"

// redirectUnconfiguredHost sends browser document requests for a host that has
// no site in the active snapshot to the admin dashboard.
//
// A host without a site has nothing to proxy, so the gateway previously fell
// through to the bot challenge / 502 page, leaving operators with no path to the
// console. Only top-level browser navigations are redirected: asset requests,
// API clients, probes and non-GET methods keep the original gateway behaviour so
// machine traffic never receives an HTML redirect.
func (m *Middleware) redirectUnconfiguredHost(w http.ResponseWriter, r *http.Request) bool {
	if m.uiHandler == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !requestAcceptsHTML(r) {
		return false
	}
	// Skip paths that address a concrete file (assets, feeds, maps). Client-side
	// routes are extensionless because the dashboard uses hash routing.
	if ext := path.Ext(r.URL.Path); ext != "" && ext != ".html" {
		return false
	}

	// Never cache: a host may gain a site later and must then stop redirecting.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Raiwall-Route", "admin-redirect")
	http.Redirect(w, r, adminDashboardPath, http.StatusFound)
	return true
}

// requestAcceptsHTML reports whether the client is a browser navigation. An
// explicit text/html in Accept is required, so curl defaults (*/*) and API
// clients (application/json) are never redirected.
func requestAcceptsHTML(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html")
}
