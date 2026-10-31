package caddy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// deadAddr returns a loopback address with nothing listening on it.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func hostOf(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestProxyWithFailoverSkipsDeadBackend(t *testing.T) {
	var hits atomic.Int32
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer live.Close()

	pool := NewUpstreamPool([]control.UpstreamTarget{
		{Dial: deadAddr(t), Weight: 1},
		{Dial: hostOf(live), Weight: 1},
	})

	for i := 0; i < 6; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := ProxyWithFailover(rec, req, pool, control.LoadBalanceRoundRobin, "203.0.113.7", http.DefaultTransport, 2)
		if err != nil || rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Fatalf("request %d: code=%d body=%q err=%v", i, rec.Code, rec.Body.String(), err)
		}
	}
	if hits.Load() != 6 {
		t.Fatalf("live backend served %d requests, want 6", hits.Load())
	}
	if pool.Backends()[0].IsHealthy() {
		t.Fatal("dead backend should be marked unhealthy by passive failures")
	}
}

func TestProxyWithFailoverReplaysBodyOnRetry(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	defer live.Close()

	pool := NewUpstreamPool([]control.UpstreamTarget{
		{Dial: deadAddr(t), Weight: 1, MaxFails: 1},
		{Dial: hostOf(live), Weight: 1},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload"))
	if err := ProxyWithFailover(rec, req, pool, control.LoadBalanceRoundRobin, "", http.DefaultTransport, 2); err != nil {
		t.Fatalf("proxy: %v", err)
	}
	if rec.Body.String() != "payload" {
		t.Fatalf("body after failover = %q, want %q", rec.Body.String(), "payload")
	}
}

func TestProxyWithFailoverAllBackendsDown(t *testing.T) {
	pool := NewUpstreamPool([]control.UpstreamTarget{
		{Dial: deadAddr(t), Weight: 1},
		{Dial: deadAddr(t), Weight: 1},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err := ProxyWithFailover(rec, req, pool, control.LoadBalanceRoundRobin, "", http.DefaultTransport, 2)
	if err == nil {
		t.Fatal("expected an error when every backend is down")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestProxyWithFailoverStalledUpstreamTimesOut(t *testing.T) {
	release := make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer stalled.Close()
	defer close(release)

	transport := &http.Transport{ResponseHeaderTimeout: 150 * time.Millisecond}
	defer transport.CloseIdleConnections()
	pool := NewUpstreamPool([]control.UpstreamTarget{{Dial: hostOf(stalled), Weight: 1}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	start := time.Now()
	err := ProxyWithFailover(rec, req, pool, control.LoadBalanceRoundRobin, "", transport, 1)
	if err == nil || rec.Code != http.StatusBadGateway {
		t.Fatalf("code=%d err=%v, want 502 with error", rec.Code, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stalled upstream held the request for %s", elapsed)
	}
}

func TestProxyWithFailoverNilPool(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ProxyWithFailover(rec, req, nil, "", "", nil, 1); err == nil || rec.Code != http.StatusBadGateway {
		t.Fatalf("code=%d err=%v, want 502 with error", rec.Code, err)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name       string
		connection string
		upgrade    string
		want       bool
	}{
		{"plain websocket", "Upgrade", "websocket", true},
		{"mixed case", "upgrade", "WebSocket", true},
		{"keep-alive list", "keep-alive, Upgrade", "websocket", true},
		{"other protocol", "Upgrade", "h2c", false},
		{"no upgrade token", "keep-alive", "websocket", false},
		{"no headers", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.connection != "" {
				r.Header.Set("Connection", tc.connection)
			}
			if tc.upgrade != "" {
				r.Header.Set("Upgrade", tc.upgrade)
			}
			if got := IsWebSocketUpgrade(r); got != tc.want {
				t.Fatalf("IsWebSocketUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
	if IsWebSocketUpgrade(nil) {
		t.Fatal("nil request must not be an upgrade")
	}
}

// startEchoUpgradeServer accepts one connection, answers the upgrade with 101,
// then echoes every byte back.
func startEchoUpgradeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
		_, _ = io.Copy(conn, br)
	}()
	return ln.Addr().String()
}

func TestProxyWebSocketEcho(t *testing.T) {
	backend := startEchoUpgradeServer(t)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = ProxyWebSocket(w, r, backend, time.Second)
	}))
	defer front.Close()

	conn, err := net.Dial("tcp", hostOf(front))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("status line = %q err=%v, want 101", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	_, _ = conn.Write([]byte("ping\n"))
	got, err := br.ReadString('\n')
	if err != nil || got != "ping\n" {
		t.Fatalf("echo = %q err=%v, want %q", got, err, "ping\n")
	}
}

func TestProxyWebSocketUpstreamDown(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	if err := ProxyWebSocket(rec, req, deadAddr(t), 200*time.Millisecond); err == nil {
		t.Fatal("expected an error for an unreachable upstream")
	}
}

func TestBackendReadmittedAfterFailTimeout(t *testing.T) {
	pool := NewUpstreamPool([]control.UpstreamTarget{
		{Dial: "10.0.0.1:80", MaxFails: 1, FailTimeout: 50 * time.Millisecond},
	})
	b := pool.Backends()[0]
	b.MarkFailure()
	if b.IsHealthy() {
		t.Fatal("backend should be down immediately after exceeding MaxFails")
	}
	time.Sleep(80 * time.Millisecond)
	if !b.IsHealthy() {
		t.Fatal("backend should be eligible again after FailTimeout")
	}
	b.MarkSuccess()
	if !b.IsHealthy() {
		t.Fatal("backend should be healthy after a successful request")
	}
}

func TestRegistryStartsActiveHealthChecks(t *testing.T) {
	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sick.Close()

	reg := NewUpstreamRegistry()
	defer reg.Close()
	targets := []control.UpstreamTarget{{
		Dial:                hostOf(sick),
		MaxFails:            1,
		HealthCheckInterval: 20 * time.Millisecond,
	}}
	pool := reg.GetOrCreatePool(targets)
	if again := reg.GetOrCreatePool(targets); again != pool {
		t.Fatal("registry should cache the pool for identical targets")
	}

	deadline := time.Now().Add(3 * time.Second)
	for pool.Backends()[0].IsHealthy() {
		if time.Now().After(deadline) {
			t.Fatal("active health check never marked the failing backend down")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
