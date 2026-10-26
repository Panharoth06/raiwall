package caddy

import (
	"context"
	"net"
	"net/http"
	neturl "net/url"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

// evaluateAuthGate selects the single browser auth authority for the request:
// the per-site gate when the site enables auth, otherwise the portal-wide
// configured gate. Both share the same HTTP 467 portal and clearance cookie.
func (m *Middleware) evaluateAuthGate(
	w http.ResponseWriter,
	r *http.Request,
	clientIP net.IP,
	appCfg *control.AppConfig,
) (handled bool, err error) {
	if appCfg != nil && appCfg.AuthEnabled {
		return m.evaluateAppAuthGate(w, r, clientIP, appCfg)
	}
	if m.globalAuthGate != nil {
		return m.evaluateGlobalAuthGate(w, r, clientIP), nil
	}
	auth.StripAuthHeaders(r.Header)
	return false, nil
}

// evaluateAppAuthGate serves the per-site zero-trust HTTP 467 challenge.
// API transports (Bearer, JSON, /api/*) and operator-configured bypass
// prefixes pass through transparently; browsers without a valid
// sl_jwt_session clearance cookie receive the branded login portal.
func (m *Middleware) evaluateAppAuthGate(
	w http.ResponseWriter,
	r *http.Request,
	clientIP net.IP,
	appCfg *control.AppConfig,
) (handled bool, err error) {
	gate := m.appAuthGateForSnapshot()
	if gate == nil {
		// Fail closed on untrusted identity headers even when the secret or
		// directory is not ready yet.
		auth.StripAuthHeaders(r.Header)
		return false, nil
	}

	// 1. Portal endpoints are handled directly, before any bypass logic.
	if handled := m.serveAuthGateEndpoint(w, r, gate, appCfg.ID, clientIP); handled {
		return true, nil
	}

	// 2. Transport fast-paths bypass the interactive challenge entirely.
	if auth.IsAPITransport(
		r.URL.Path,
		r.Header.Get("Accept"),
		r.Header.Get("Authorization"),
		r.Header.Get("X-Requested-With"),
	) {
		// Keep already-cleared identity claims for API callers too.
		gate.Claims(r)
		return false, nil
	}

	// 3. Site-configured path bypasses.
	if auth.PathBypassed(r.URL.Path, appCfg.AuthBypassPaths) {
		return false, nil
	}

	// 4. Cleared session: inject verified identity headers upstream.
	if gate.Claims(r) != nil {
		return false, nil
	}

	// 5. Unauthenticated browser: serve the HTTP 467 branded challenge.
	geo := m.lookupGeo(clientIP)
	gate.HandleChallenge(w, r, auth.ChallengeOptions{
		AppID:    appCfg.ID,
		Host:     r.Host,
		Target:   r.URL.RequestURI(),
		ClientIP: ipString(clientIP),
		Country:  geo.Country,
	}, "")
	return true, nil
}

// evaluateGlobalAuthGate applies the global `auth` block to hosts without
// per-site auth enabled. API transports receive JSON 401 instead of HTML.
func (m *Middleware) evaluateGlobalAuthGate(w http.ResponseWriter, r *http.Request, clientIP net.IP) bool {
	gate := m.globalAuthGate
	if handled := m.serveAuthGateEndpoint(w, r, gate, "", clientIP); handled {
		return true
	}

	// Cleared sessions inject verified identity headers upstream. Claims also
	// strips spoofed X-Auth-* headers for every request.
	if gate.Claims(r) != nil {
		return false
	}

	if gate.AllowsPath(r.URL.Path) {
		return false
	}

	if auth.IsAPITransport(
		r.URL.Path,
		r.Header.Get("Accept"),
		r.Header.Get("Authorization"),
		r.Header.Get("X-Requested-With"),
	) {
		auth.WriteUnauthorizedAPI(w, auth.AppAuthLoginPath)
		return true
	}

	geo := m.lookupGeo(clientIP)
	gate.HandleChallenge(w, r, auth.ChallengeOptions{
		Host:     r.Host,
		Target:   r.URL.RequestURI(),
		ClientIP: ipString(clientIP),
		Country:  geo.Country,
	}, "")
	return true
}

// serveAuthGateEndpoint dispatches portal routes shared by both gate modes.
func (m *Middleware) serveAuthGateEndpoint(
	w http.ResponseWriter,
	r *http.Request,
	gate *auth.AppAuthGate,
	appID string,
	clientIP net.IP,
) bool {
	if gate == nil {
		return false
	}
	clientIPStr := ipString(clientIP)
	geo := m.lookupGeo(clientIP)

	switch r.URL.Path {
	case auth.LegacyAuthLoginPath:
		// Retired legacy login page: keep bookmarks working without a second UI.
		target := auth.AppAuthLoginPath
		if redirect := r.URL.Query().Get("redirect"); redirect != "" {
			target += "?redirect=" + neturl.QueryEscape(redirect)
		}
		http.Redirect(w, r, target, http.StatusFound)
	case auth.AppAuthLoginPath:
		gate.HandleLogin(w, r, appID, clientIPStr, geo.Country)
	case auth.AppAuthLogoutPath:
		gate.ServeLogout(w, r)
	case auth.AppAuthSSOPath:
		gate.HandleSSOStart(w, r, appID)
	case auth.AppAuthCallbackPath:
		gate.HandleSSOCallback(w, r)
	default:
		return false
	}

	if m.logger != nil {
		m.logger.Info("auth portal endpoint",
			zap.String("app_id", appID),
			zap.String("path", r.URL.Path),
			zap.String("host", r.Host),
			zap.String("client_ip", clientIPStr))
	}
	return true
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// appAuthGateForSnapshot lazily provisions the gate against the live snapshot
// secret so secret rotations invalidate prior clearance cookies. Reads and
// writes of the cached gate are mutex-guarded: pipeline runs per-request on
// concurrent goroutines.
func (m *Middleware) appAuthGateForSnapshot() *auth.AppAuthGate {
	snap := control.LoadSnapshot()
	if snap == nil || snap.AppAuthSessionSecret == "" {
		// No secret compiled yet; bootstrap the settings row once so the
		// next snapshot compile carries it (Provision also best-effort).
		m.appAuthSecretOnce.Do(func() {
			if m.controlStore != nil {
				if _, err := m.resolveAppAuthSecret(context.Background()); err != nil && m.logger != nil {
					m.logger.Warn("app auth secret bootstrap failed", zap.Error(err))
				}
			}
		})
		return nil
	}

	m.appAuthGateMu.Lock()
	defer m.appAuthGateMu.Unlock()

	if m.appAuthGate == nil || m.appAuthGateSecret != snap.AppAuthSessionSecret {
		gate := m.loadAppAuthGate(&snap.AppAuthSessionSecret)
		if gate == nil {
			return nil
		}
		m.appAuthGate = gate
		m.appAuthGateSecret = snap.AppAuthSessionSecret
	}
	return m.appAuthGate
}
