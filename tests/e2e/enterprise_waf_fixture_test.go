//go:build integration

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

type inMemoryRoundTripper struct {
	handler http.Handler
}

func (m *inMemoryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

type enterpriseTestFixture struct {
	mw          *caddy.Middleware
	backendMux  *http.ServeMux
	apiBackend  *http.ServeMux
	banManager  *rate.BanManager
	waitingRoom *rate.WaitingRoomManager
	ipGroupMgr  *acl.IPGroupManager
	authGateway *auth.AppAuthGate
	sessionMgr  *auth.SessionManager
	defaultNext *e2eNextHandler
}

func setupEnterpriseFixture(t *testing.T) *enterpriseTestFixture {
	t.Helper()

	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","backend":"default"}`))
	})

	apiBackend := http.NewServeMux()
	apiBackend.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Received-Host", r.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","backend":"api_v2"}`))
	})

	mw := &caddy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
		TelemetryConfig: &caddy.TelemetrySettings{
			StorageType: "sqlite",
			StoragePath: "file:test_telemetry?mode=memory&cache=shared",
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	t.Cleanup(cancel)

	err := mw.Provision(caddyCtx)
	require.NoError(t, err)

	if mw.UpstreamRegistry() != nil {
		mw.UpstreamRegistry().SetTransport(&inMemoryRoundTripper{handler: apiBackend})
	}

	banMgr := rate.NewBanManager(nil)
	mw.SetBanManager(banMgr)

	wm := rate.NewWaitingRoomManager(rate.WaitingRoomConfig{
		MaxConcurrentInFlight: 2,
		MaxQueueDepth:         10,
		AdmissionRate:         5,
		AdmissionTokenTTL:     10 * time.Minute,
		TargetPaths:           []string{"/queue-target"},
		Secret:                "e2e-enterprise-waiting-room-secret-key-32b",
	})
	mw.SetWaitingRoom(wm)

	ipMgr := acl.NewIPGroupManager(acl.NewBARTTable())
	mw.SetIPGroupManager(ipMgr)

	authGate := auth.NewAppAuthGate("e2e-enterprise-auth-cookie-secret-32b", nil, nil,
		auth.WithBypassPaths(
			"/catalog*", "/search*", "/exec*", "/files*", "/admin*", "/.git*",
			"/api/*", "/public*", "/queue-target*", "/healthz*", "/submit*",
		),
	)
	mw.SetGlobalAuthGate(authGate)

	return &enterpriseTestFixture{
		mw:          mw,
		backendMux:  backendMux,
		apiBackend:  apiBackend,
		banManager:  banMgr,
		waitingRoom: wm,
		ipGroupMgr:  ipMgr,
		authGateway: authGate,
		sessionMgr:  authGate.SessionManager(),
		defaultNext: &e2eNextHandler{handler: backendMux},
	}
}
