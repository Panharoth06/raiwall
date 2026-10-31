package caddy

import (
	"net"
	"net/http"
	"net/url"
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
	if m.uiHandler == nil || !m.isConsoleHost(r.Host) {
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

// isConsoleHost reports whether the request targets control.public_url. Unknown
// hosts no longer reveal or redirect to the dashboard.
func (m *Middleware) isConsoleHost(host string) bool {
	if m.ControlConfig == nil || strings.TrimSpace(m.ControlConfig.PublicURL) == "" {
		return false
	}
	parsed, err := url.Parse(m.ControlConfig.PublicURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(hostOnly(host), hostOnly(parsed.Host))
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

// requestAcceptsHTML reports whether the client is a browser navigation. An
// explicit text/html in Accept is required, so curl defaults (*/*) and API
// clients (application/json) are never redirected.
func requestAcceptsHTML(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html")
}
