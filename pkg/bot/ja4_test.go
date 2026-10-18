package bot

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestComputeJA4(t *testing.T) {
	t.Run("nil hello", func(t *testing.T) {
		got := ComputeJA4(nil)
		if got != "" {
			t.Errorf("ComputeJA4(nil) = %q, want empty", got)
		}
	})

	t.Run("valid ClientHelloInfo", func(t *testing.T) {
		hello := &tls.ClientHelloInfo{
			CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
			ServerName:        "example.com",
			SupportedProtos:   []string{"h2", "http/1.1"},
			SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		}

		ja4 := ComputeJA4(hello)
		if ja4 == "" {
			t.Errorf("ComputeJA4 returned empty string for valid ClientHelloInfo")
		}
		// JA4 format: a_b_c
		if len(ja4) < 10 {
			t.Errorf("ComputeJA4 returned unexpectedly short string: %s", ja4)
		}
	})
}

func TestContextJA4(t *testing.T) {
	ctx := context.Background()
	if got := GetJA4(ctx); got != "" {
		t.Errorf("GetJA4(empty ctx) = %q, want empty", got)
	}

	testFingerprint := "t13d1516h2_8daaf6152771_0100742d1fc0"
	ctx = WithJA4(ctx, testFingerprint)
	if got := GetJA4(ctx); got != testFingerprint {
		t.Errorf("GetJA4(ctx) = %q, want %q", got, testFingerprint)
	}

	if got := GetJA4(nil); got != "" {
		t.Errorf("GetJA4(nil) = %q, want empty", got)
	}
}

func TestExtractJA4(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		wantJA4    string
	}{
		{
			name: "nil request",
			setupReq: func() *http.Request {
				return nil
			},
			wantJA4: "",
		},
		{
			name: "context present",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				ctx := WithJA4(req.Context(), "ja4-from-context")
				req.Header.Set("X-JA4-Fingerprint", "ja4-from-header")
				return req.WithContext(ctx)
			},
			wantJA4: "ja4-from-context",
		},
		{
			name: "X-JA4-Fingerprint header fallback",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				req.Header.Set("X-JA4-Fingerprint", "ja4-from-x-header")
				req.Header.Set("JA4", "ja4-from-ja4-header")
				return req
			},
			wantJA4: "ja4-from-x-header",
		},
		{
			name: "JA4 header fallback",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				req.Header.Set("JA4", "  ja4-from-plain-header  ")
				return req
			},
			wantJA4: "ja4-from-plain-header",
		},
		{
			name: "no ja4 source",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			},
			wantJA4: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			got := ExtractJA4(req)
			if got != tt.wantJA4 {
				t.Errorf("ExtractJA4() = %q, want %q", got, tt.wantJA4)
			}
		})
	}
}

func TestDirectTLSCapturer(t *testing.T) {
	capturer := NewDirectTLSCapturer()
	if capturer == nil {
		t.Fatal("NewDirectTLSCapturer returned nil")
	}

	// Test nil hello
	_, err := capturer.GetConfigForClient(nil)
	if err != nil {
		t.Errorf("GetConfigForClient(nil) returned error: %v", err)
	}

	// Test with nil Conn (must not panic)
	helloNoConn := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		ServerName:        "example.com",
		SupportedVersions: []uint16{tls.VersionTLS13},
	}
	_, err = capturer.GetConfigForClient(helloNoConn)
	if err != nil {
		t.Errorf("GetConfigForClient(helloNoConn) returned error: %v", err)
	}

	// Test with valid Conn
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		ServerName:        "example.com",
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedProtos:   []string{"h2", "http/1.1"},
		Conn:              serverConn,
	}
	_, err = capturer.GetConfigForClient(hello)
	if err != nil {
		t.Errorf("GetConfigForClient(hello) returned error: %v", err)
	}

	capturer.ConnStateCallback(serverConn, http.StateActive)
	capturer.ConnStateCallback(serverConn, http.StateClosed)

	// Test handler wrap
	called := false
	handler := capturer.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("wrapped handler was not called")
	}
}
