//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

// pipeHijackResponseWriter connects an http.ResponseWriter to a net.Pipe for testing hijacking.
type pipeHijackResponseWriter struct {
	*httptest.ResponseRecorder
	serverConn net.Conn
	hijacked   bool
}

func (p *pipeHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	p.hijacked = true
	rw := bufio.NewReadWriter(bufio.NewReader(p.serverConn), bufio.NewWriter(p.serverConn))
	return p.serverConn, rw, nil
}

func (p *pipeHijackResponseWriter) Flush() {
	p.ResponseRecorder.Flush()
}

func TestEndToEndHTTPProxying(t *testing.T) {
	// 1. Mock upstream backend
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "BackendServer/1.0")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("X-Safe-Header", "true")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(body)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","proto":"` + r.Proto + `"}`))
	})

	// 2. Setup Raiwall Middleware
	mw := &caddy.Middleware{
		Mode:         "defense",
		StripHeaders: []string{"Server", "X-Powered-By"},
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	mockNext := &e2eNextHandler{handler: backendMux}

	// 3. Test HTTP/1.1 GET Request
	req1 := httptest.NewRequest("GET", "http://example.com/api/data", nil)
	req1.Proto = "HTTP/1.1"
	req1.ProtoMajor = 1
	req1.ProtoMinor = 1
	req1.RemoteAddr = "203.0.113.10:12345"
	rec1 := httptest.NewRecorder()

	if err := mw.ServeHTTP(rec1, req1, mockNext); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if rec1.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec1.Code)
	}
	if rec1.Header().Get("Server") != "" {
		t.Errorf("Server header was not stripped: %s", rec1.Header().Get("Server"))
	}
	if rec1.Header().Get("X-Powered-By") != "" {
		t.Errorf("X-Powered-By header was not stripped: %s", rec1.Header().Get("X-Powered-By"))
	}
	if rec1.Header().Get("X-Safe-Header") != "true" {
		t.Errorf("safe header was corrupted: %s", rec1.Header().Get("X-Safe-Header"))
	}

	// 4. Test HTTP/2 POST Request with JSON Body
	postData := map[string]string{"user": "alice", "action": "login"}
	postBytes, _ := json.Marshal(postData)

	req2 := httptest.NewRequest("POST", "http://example.com/api/data", bytes.NewReader(postBytes))
	req2.Proto = "HTTP/2.0"
	req2.ProtoMajor = 2
	req2.ProtoMinor = 0
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "198.51.100.20:54321"
	rec2 := httptest.NewRecorder()

	if err := mw.ServeHTTP(rec2, req2, mockNext); err != nil {
		t.Fatalf("ServeHTTP error on POST: %v", err)
	}

	if rec2.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "alice") {
		t.Errorf("echoed body missing alice: %s", rec2.Body.String())
	}
}

func TestEndToEndWebSocketAndDynamicModeSwitch(t *testing.T) {
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	// Setup threat detection engine
	mockEng := waf.NewMockEngine()
	mockEng.InspectRequestHandler = func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		if strings.Contains(ctx.Path, "malicious") || strings.Contains(ctx.Query, "sqli") {
			return &waf.Verdict{
				Action:     waf.ActionBlock,
				RuleID:     "INJECTION_DETECTION_01",
				Reason:     "Attack detected in query/path",
				StatusCode: http.StatusForbidden,
			}, nil
		}
		return waf.VerdictAllow, nil
	}

	mw := &caddy.Middleware{
		Mode: "defense",
	}
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}
	mw.SetEngine(mockEng)

	// Upstream WebSocket echo handler
	wsMux := http.NewServeMux()
	wsMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}

		// Perform WebSocket handshake
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "cannot hijack", http.StatusInternalServerError)
			return
		}

		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo loop
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			_, _ = rw.WriteString("ECHO:" + line)
			_ = rw.Flush()
		}
	})

	wsNext := &e2eNextHandler{handler: wsMux}

	// 1. Establish persistent live connection (WebSocket simulation over in-memory full-duplex pipe)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	rec := &pipeHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		serverConn:       serverConn,
	}

	reqWS := httptest.NewRequest("GET", "http://example.com/ws", nil)
	reqWS.Header.Set("Upgrade", "websocket")
	reqWS.Header.Set("Connection", "Upgrade")

	wsErrCh := make(chan error, 1)
	go func() {
		wsErrCh <- mw.ServeHTTP(rec, reqWS, wsNext)
	}()

	clientReader := bufio.NewReader(clientConn)
	clientWriter := bufio.NewWriter(clientConn)

	// Send message over live connection
	_, err := clientWriter.WriteString("hello websocket\n")
	if err != nil {
		t.Fatalf("failed to write to client connection: %v", err)
	}
	_ = clientWriter.Flush()

	echoResp, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read from live connection: %v", err)
	}
	if !strings.Contains(echoResp, "ECHO:hello websocket") {
		t.Errorf("expected echo response, got: %s", echoResp)
	}

	// 2. Validate Defense Mode blocking on new requests
	reqThreat := httptest.NewRequest("GET", "http://example.com/api?query=sqli", nil)
	recThreat := httptest.NewRecorder()
	if err := mw.ServeHTTP(recThreat, reqThreat, wsNext); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if recThreat.Code != http.StatusForbidden {
		t.Errorf("defense mode expected 403, got %d", recThreat.Code)
	}
	if !strings.Contains(recThreat.Body.String(), "Request Blocked") {
		t.Errorf("expected block screen, got %s", recThreat.Body.String())
	}

	// 3. Dynamic Mode Flip to Offline on live connection
	offlineApp := &control.AppConfig{
		ID:        "app-live",
		Hostnames: []string{"example.com"},
		Mode:      control.ModeOffline,
	}
	control.StoreSnapshot(control.NewConfigSnapshot(2, control.ModeDefense, []*control.AppConfig{offlineApp}))

	// New incoming HTTP request gets 503
	reqNew := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	recNew := httptest.NewRecorder()
	if err := mw.ServeHTTP(recNew, reqNew, wsNext); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if recNew.Code != http.StatusServiceUnavailable {
		t.Errorf("offline mode expected 503, got %d", recNew.Code)
	}

	// VERIFY LIVE CONNECTION WAS NOT DROPPED!
	// Send another message over the previously opened WebSocket pipe
	_, err = clientWriter.WriteString("message during offline mode\n")
	if err != nil {
		t.Fatalf("live socket dropped after mode flip: %v", err)
	}
	_ = clientWriter.Flush()

	echoDuringOffline, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read from live connection during offline: %v", err)
	}
	if !strings.Contains(echoDuringOffline, "ECHO:message during offline mode") {
		t.Errorf("expected echo response during offline, got: %s", echoDuringOffline)
	}

	// 4. Dynamic Mode Flip to Audit Mode
	auditApp := &control.AppConfig{
		ID:        "app-live",
		Hostnames: []string{"example.com"},
		Mode:      control.ModeAudit,
	}
	control.StoreSnapshot(control.NewConfigSnapshot(3, control.ModeDefense, []*control.AppConfig{auditApp}))

	// Upstream handler for test API
	testAPIMux := http.NewServeMux()
	testAPIMux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("threat allowed under audit mode"))
	})
	testNext := &e2eNextHandler{handler: testAPIMux}

	recAudit := httptest.NewRecorder()
	if err := mw.ServeHTTP(recAudit, reqThreat, testNext); err != nil {
		t.Fatalf("ServeHTTP error under audit: %v", err)
	}
	if recAudit.Code != http.StatusOK {
		t.Errorf("audit mode should pass through threat, got status %d", recAudit.Code)
	}
	if recAudit.Body.String() != "threat allowed under audit mode" {
		t.Errorf("expected audit response, got: %s", recAudit.Body.String())
	}

	// Live socket still operational
	_, err = clientWriter.WriteString("message during audit mode\n")
	if err != nil {
		t.Fatalf("live socket failed in audit mode: %v", err)
	}
	_ = clientWriter.Flush()

	echoDuringAudit, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read from live connection during audit: %v", err)
	}
	if !strings.Contains(echoDuringAudit, "ECHO:message during audit mode") {
		t.Errorf("expected echo response during audit, got: %s", echoDuringAudit)
	}

	// Clean shutdown of live connection
	_ = clientConn.Close()
	select {
	case <-wsErrCh:
	case <-time.After(1 * time.Second):
	}
}

type e2eNextHandler struct {
	handler http.Handler
}

func (e *e2eNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	e.handler.ServeHTTP(w, r)
	return nil
}
