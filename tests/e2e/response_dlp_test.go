//go:build integration

package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDLPFixture(t *testing.T) (*caddy.Middleware, *http.ServeMux, *e2eNextHandler) {
	t.Helper()

	backendMux := http.NewServeMux()

	// 1. Benign clean JSON
	backendMux.HandleFunc("/benign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","message":"welcome to test backend"}`))
	})

	// 2. Sensitive data body (Visa PAN, JWT, AWS key, generic secret)
	backendMux.HandleFunc("/sensitive", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := `{"card":"4111 1111 1111 1111","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_m1sPqVv9_naGsm_4h_m_g_l_r_o_c_k_s","key":"AKIAIOSFODNN7EXAMPLE","client_secret":"sec_live_9876543210abcdef"}`
		_, _ = w.Write([]byte(body))
	})

	// 3. Sensitive header (Auth token)
	backendMux.HandleFunc("/header-secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Api-Key", "Basic secretkey12345")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// 4. Binary non-inspectable content (image/png) containing PAN string
	backendMux.HandleFunc("/binary-pan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake-png-binary-content-4111 1111 1111 1111-trailing"))
	})

	// 5. Large payload (>8 MiB) with PAN
	backendMux.HandleFunc("/large-payload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		prefix := `{"status":"large","card":"4111 1111 1111 1111","padding":"`
		_, _ = w.Write([]byte(prefix))
		// 8.5 MiB chunk
		chunk := bytes.Repeat([]byte("A"), 1024*1024)
		for i := 0; i < 9; i++ {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	})

	// 6. Gzip-compressed sensitive body
	backendMux.HandleFunc("/compressed-sensitive", func(w http.ResponseWriter, r *http.Request) {
		raw := []byte(`{"card":"4111 1111 1111 1111","key":"AKIAIOSFODNN7EXAMPLE"}`)
		var gzipped bytes.Buffer
		gw := gzip.NewWriter(&gzipped)
		_, _ = gw.Write(raw)
		_ = gw.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipped.Bytes())
	})

	// 7. SSE streaming endpoint
	backendMux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: hello\n\n"))
		if ok {
			flusher.Flush()
		}
	})

	// 8. Outbound SQL syntax error leakage
	backendMux.HandleFunc("/sql-error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT' at line 1"))
	})

	enabled := true
	mw := &caddy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
		CRSEnabled:      true,
		CRSMode:         "block",
		ResponseConfig: &caddy.ResponseSettings{
			Enabled:        &enabled,
			Mode:           "audit",
			InspectHeaders: &enabled,
			InspectBody:    &enabled,
			BodyLimit:      1024 * 1024,
			HardCap:        8 * 1024 * 1024,
			Decompress:     &enabled,
			DLP: &caddy.DLPSettings{
				Enabled:           &enabled,
				Action:            "audit",
				DetectPAN:         &enabled,
				DetectSecrets:     &enabled,
				DetectJWT:         &enabled,
				DetectPrivateKeys: &enabled,
				Redaction:         "[REDACTED]",
				MaxScanBytes:      1024 * 1024,
			},
		},
		ControlConfig: &caddy.ControlSettings{
			DBPath:         "file:" + filepath.Join(t.TempDir(), "control-dlp.db"),
			AllowBasicAuth: true,
			SessionSecure:  new(bool),
			BootstrapAdmin: &caddy.BootstrapAdminSettings{
				Username: "admin", Password: "admin", Role: "admin",
			},
		},
		TelemetryConfig: &caddy.TelemetrySettings{
			StorageType: "sqlite",
			StoragePath: "file:test_telemetry_dlp?mode=memory&cache=shared",
		},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	t.Cleanup(cancel)

	err := mw.Provision(caddyCtx)
	require.NoError(t, err)

	authGate := auth.NewAppAuthGate("e2e-dlp-auth-cookie-secret-32b", nil, nil,
		auth.WithBypassPaths("/*"),
	)
	mw.SetGlobalAuthGate(authGate)

	next := &e2eNextHandler{handler: backendMux}
	return mw, backendMux, next
}

func makeSnapshotWithResponse(version uint64, mode control.RunMode, respMode string, dlpAction string) *control.ConfigSnapshot {
	enabled := true
	snap := control.NewConfigSnapshot(version, mode, nil)
	snap.WAFPolicy = &control.WAFPolicySnapshot{
		DetectionMode: string(mode),
		Sensitivity:   "medium",
		Response: &control.ResponsePolicySnapshot{
			Enabled:        &enabled,
			Mode:           respMode,
			InspectHeaders: &enabled,
			InspectBody:    &enabled,
			BodyLimit:      1024 * 1024,
			HardCap:        8 * 1024 * 1024,
			Decompress:     &enabled,
			ContentTypes:   control.DefaultContentTypes(),
			DLP: &control.DLPPolicySnapshot{
				Enabled:           &enabled,
				Action:            dlpAction,
				DetectPAN:         &enabled,
				DetectSecrets:     &enabled,
				DetectJWT:         &enabled,
				DetectPrivateKeys: &enabled,
				Redaction:         "[REDACTED]",
				MaxScanBytes:      1024 * 1024,
			},
		},
	}
	return snap
}

func TestResponseInspection_FullLifecycle(t *testing.T) {
	mw, _, next := setupDLPFixture(t)

	execReq := func(method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.RemoteAddr = "192.0.2.200:43210"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		err := mw.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		return rec
	}

	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	authHeaders := map[string]string{"Authorization": basicAuth}

	t.Run("1. Benign request passes through with 200 OK", func(t *testing.T) {
		rec := execReq(http.MethodGet, "/benign", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "welcome to test backend")
	})

	t.Run("2. Inbound SQLi threat is blocked with 403 Forbidden", func(t *testing.T) {
		rec := execReq(http.MethodGet, "/search?q=%27%20OR%201=1--", "", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("3. Outbound DLP in Audit Mode allows response with 200 OK", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(201, control.ModeDefense, "audit", "audit"))
		rec := execReq(http.MethodGet, "/sensitive", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "4111 1111 1111 1111")
		assert.Contains(t, rec.Body.String(), "AKIAIOSFODNN7EXAMPLE")

		// Query telemetry to confirm event recorded
		time.Sleep(600 * time.Millisecond)
		telemRec := execReq(http.MethodGet, "/.raiwall/api/v1/telemetry/events?limit=5", "", authHeaders)
		assert.Equal(t, http.StatusOK, telemRec.Code)
		assert.Contains(t, telemRec.Body.String(), "dlp_")
	})

	t.Run("4. Outbound DLP in Block Mode blocks response with 403 Forbidden", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(202, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/sensitive", "", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.NotContains(t, rec.Body.String(), "4111 1111 1111 1111")
		assert.NotContains(t, rec.Body.String(), "AKIAIOSFODNN7EXAMPLE")
	})

	t.Run("5. Outbound DLP in Redact Mode masks secrets with [REDACTED]", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(203, control.ModeDefense, "redact", "redact"))
		rec := execReq(http.MethodGet, "/sensitive", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		bodyStr := rec.Body.String()
		assert.NotContains(t, bodyStr, "4111 1111 1111 1111")
		assert.NotContains(t, bodyStr, "AKIAIOSFODNN7EXAMPLE")
		assert.NotContains(t, bodyStr, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
		assert.NotContains(t, bodyStr, "sec_live_9876543210abcdef")
		assert.Contains(t, bodyStr, "[REDACTED]")
	})

	t.Run("6. Outbound DLP Header Detection in Block Mode returns 403", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(204, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/header-secret", "", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("7. Non-inspectable content-type (image/png) passes through unblocked", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(205, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/binary-pan", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "image/png", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "4111 1111 1111 1111")
	})

	t.Run("8. Large payload (>8 MiB) streams uninspected without error", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(206, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/large-payload", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, rec.Body.Len() > 8*1024*1024, "body should be >8 MiB")
	})

	t.Run("9. Gzip-compressed response is inspected and handled correctly", func(t *testing.T) {
		// In block mode, compressed response containing PAN is blocked
		control.StoreSnapshot(makeSnapshotWithResponse(207, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/compressed-sensitive", "", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		// In redact mode, compressed response is redacted and Content-Encoding stripped
		control.StoreSnapshot(makeSnapshotWithResponse(208, control.ModeDefense, "redact", "redact"))
		recRedact := execReq(http.MethodGet, "/compressed-sensitive", "", nil)
		assert.Equal(t, http.StatusOK, recRedact.Code)
		assert.Contains(t, recRedact.Body.String(), "[REDACTED]")
		assert.NotContains(t, recRedact.Body.String(), "4111 1111 1111 1111")
		assert.Empty(t, recRedact.Header().Get("Content-Encoding"), "Content-Encoding should be stripped after body redaction")
	})

	t.Run("10. SSE streaming (text/event-stream) is unaffected", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(209, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/sse", "", nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "data: hello")
	})

	t.Run("11. Paired Coraza CRS outbound rule blocks database error leakage", func(t *testing.T) {
		control.StoreSnapshot(makeSnapshotWithResponse(210, control.ModeDefense, "block", "block"))
		rec := execReq(http.MethodGet, "/sql-error", "", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
