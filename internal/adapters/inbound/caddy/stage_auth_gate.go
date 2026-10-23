package caddy

import (
	"context"
	"net"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

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
	if appCfg == nil || !appCfg.AuthEnabled || m.controlStore == nil {
		return false, nil
	}

	gate := m.appAuthGateForSnapshot()
	if gate == nil {
		return false, nil
	}

	// 1. Gate endpoints are handled directly, before any bypass logic.
	if r.URL.Path == auth.AppAuthLoginPath {
		clientIPStr := ipString(clientIP)
		geo := m.lookupGeo(clientIP)
		gate.HandleLogin(w, r, appCfg.ID, clientIPStr, geo.Country)
		if m.logger != nil {
			m.logger.Info("app auth gate processed login",
				zap.String("app_id", appCfg.ID),
				zap.String("host", r.Host),
				zap.String("client_ip", clientIPStr))
		}
		return true, nil
	}
	if r.URL.Path == auth.AppAuthLogoutPath {
		gate.ServeLogout(w, r)
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
	gate.HandleChallenge(w, r, auth.ChallengeOptions{
		AppID:    appCfg.ID,
		Host:     r.Host,
		Target:   r.URL.RequestURI(),
		ClientIP: ipString(clientIP),
	}, "")
	return true, nil
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
