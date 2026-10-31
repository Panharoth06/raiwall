package caddy

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

const readinessProbeTimeout = 2 * time.Second

// serveHealth answers liveness and readiness probes before WAF, auth, and the
// admin allowlist. Probes must work even when the console is restricted.
func (m *Middleware) serveHealth(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/.raiwall/healthz", "/.raiwall/readyz":
	default:
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if r.URL.Path == "/.raiwall/healthz" {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return true
	}

	// Readiness is unauthenticated and bypasses the console allowlist, so it
	// reports only the aggregate state. Authenticated /status exposes the
	// per-component checks needed to diagnose a failure.
	checks := m.Readiness(r.Context())
	ready := true
	for _, ok := range checks {
		if !ok {
			ready = false
		}
	}
	if !ready {
		writeHealthJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
		return true
	}
	writeHealthJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	return true
}

// Readiness reports the dependencies a serving replica needs. The control API
// reuses it for /status.
func (m *Middleware) Readiness(ctx context.Context) map[string]bool {
	checks := make(map[string]bool, 4)

	if m.controlStore != nil {
		probeCtx, cancel := context.WithTimeout(ctx, readinessProbeTimeout)
		checks["database"] = m.controlStore.Ping(probeCtx) == nil
		cancel()
	} else {
		checks["database"] = false
	}

	snap := control.GetActiveSnapshot()
	checks["snapshot"] = snap != nil && snap.Version >= 1

	if m.redisClient != nil {
		probeCtx, cancel := context.WithTimeout(ctx, readinessProbeTimeout)
		checks["redis"] = m.redisClient.Ping(probeCtx) == nil
		cancel()

		remote := control.RemoteAppliedStatus()
		checks["snapshot_synced"] = remote.AppliedVersion == 0 || snap == nil || remote.AppliedVersion >= snap.Version
	}
	return checks
}

func writeHealthJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
