package caddy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func TestResponseInterceptorHeaderStripping(t *testing.T) {
	m := setupTestMiddleware(t, "defense", waf.NewPassthroughEngine())

	upstreamHeaders := http.Header{
		"Server":             {"Apache/2.4.41 (Ubuntu)"},
		"X-Powered-By":       {"PHP/7.4.3"},
		"X-AspNet-Version":   {"4.0.30319"},
		"Content-Type":       {"application/json"},
		"X-Custom-Safe-Head": {"safe-value"},
	}

	mockH := newMockHandler(http.StatusNotFound, upstreamHeaders, []byte(`{"error":"not found"}`))

	req := httptest.NewRequest("GET", "http://example.com/missing", nil)
	rec := httptest.NewRecorder()

	err := m.ServeHTTP(rec, req, mockH)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify status code captured
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// Verify stripped sensitive headers
	for _, badHeader := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if val := rec.Header().Get(badHeader); val != "" {
			t.Errorf("expected header %q to be stripped, got %q", badHeader, val)
		}
	}

	// Verify safe headers preserved
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not preserved: %v", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Custom-Safe-Head") != "safe-value" {
		t.Errorf("safe header not preserved: %v", rec.Header().Get("X-Custom-Safe-Head"))
	}
}

// flushHijackRecorder implements http.ResponseWriter, http.Flusher, and http.Hijacker.
type flushHijackRecorder struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
}

func (f *flushHijackRecorder) Flush() {
	f.flushed = true
	f.ResponseRecorder.Flush()
}

func (f *flushHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	client, server := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestResponseInterceptorFlusherAndHijacker(t *testing.T) {
	rec := &flushHijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	interceptor := NewResponseInterceptor(rec, DefaultSensitiveHeaders)

	// Test Flush delegation
	interceptor.Flush()
	if !rec.flushed {
		t.Errorf("expected Flush() to be delegated to underlying recorder")
	}

	// Test Hijack delegation
	conn, rw, err := interceptor.Hijack()
	if err != nil {
		t.Fatalf("unexpected Hijack error: %v", err)
	}
	if !rec.hijacked {
		t.Errorf("expected Hijack() to be delegated")
	}
	if conn != nil {
		_ = conn.Close()
	}
	_ = rw
}

func TestResponseInterceptorInformational1xx(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := NewResponseInterceptor(rec, []string{"Server", "X-Powered-By"})

	// 1. Send 103 Early Hints with a Link header and sensitive header
	interceptor.Header().Set("Link", "</style.css>; rel=preload; as=style")
	interceptor.Header().Set("Server", "Backend/1.0")
	interceptor.WriteHeader(http.StatusEarlyHints)

	if interceptor.StatusCode() != http.StatusEarlyHints {
		t.Errorf("interceptor status after 103 = %d, want 103", interceptor.StatusCode())
	}

	// 2. Now send final 200 OK with body and more headers
	interceptor.Header().Set("X-Custom", "active")
	interceptor.WriteHeader(http.StatusOK)
	_, _ = interceptor.Write([]byte("final body"))

	if interceptor.StatusCode() != http.StatusOK {
		t.Errorf("final interceptor status = %d, want 200", interceptor.StatusCode())
	}
	if rec.Header().Get("Server") != "" {
		t.Errorf("Server header was not stripped on 200 OK: %s", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Custom") != "active" {
		t.Errorf("X-Custom header missing on 200 OK")
	}
	if rec.Body.String() != "final body" {
		t.Errorf("body = %q, want 'final body'", rec.Body.String())
	}
}

func TestResponseInterceptor_CompressedHTMLNotCorrupted(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := NewResponseInterceptor(rec, nil)
	interceptor.SetHoneypotInjector(bot.NewHoneypotInjector(bot.DefaultTrapPath))

	interceptor.Header().Set("Content-Type", "text/html; charset=utf-8")
	interceptor.Header().Set("Content-Encoding", "gzip")

	// Fake gzip byte sequence
	fakeGzip := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x02, 0x03}
	interceptor.WriteHeader(http.StatusOK)
	_, _ = interceptor.Write(fakeGzip)
	interceptor.Finish()

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)

	// Body must be byte-for-byte identical to the input gzip stream with no honeypot appended
	if !bytes.Equal(body, fakeGzip) {
		t.Errorf("Compressed HTML body corrupted: got %v, want %v", body, fakeGzip)
	}
}

func TestResponseInterceptor_NotModified304(t *testing.T) {
	rec := httptest.NewRecorder()
	interceptor := NewResponseInterceptor(rec, nil)
	interceptor.SetHoneypotInjector(bot.NewHoneypotInjector(bot.DefaultTrapPath))

	interceptor.Header().Set("Content-Type", "text/html; charset=utf-8")
	interceptor.WriteHeader(http.StatusNotModified)
	interceptor.Finish()

	res := rec.Result()
	if res.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if len(body) != 0 {
		t.Errorf("expected empty body for 304, got %d bytes", len(body))
	}
}
