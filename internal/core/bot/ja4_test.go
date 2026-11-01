package bot

import (
	"context"
	"crypto/tls"
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

func TestExtractJA4IgnoresHeaders(t *testing.T) {
	if got := ExtractJA4(nil); got != "" {
		t.Errorf("ExtractJA4(nil) = %q, want empty", got)
	}

	spoofed := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	spoofed.Header.Set(HeaderXJA4Fingerprint, "ja4-from-header")
	spoofed.Header.Set(HeaderJA4, "ja4-from-plain-header")
	if got := ExtractJA4(spoofed); got != "" {
		t.Errorf("ExtractJA4 must not read client headers, got %q", got)
	}

	captured := spoofed.WithContext(WithJA4(spoofed.Context(), "ja4-from-handshake"))
	if got := ExtractJA4(captured); got != "ja4-from-handshake" {
		t.Errorf("ExtractJA4 = %q, want the handshake value", got)
	}
}

func TestJA4FromHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"none", nil, ""},
		{"x-header wins", map[string]string{HeaderXJA4Fingerprint: "a", HeaderJA4: "b"}, "a"},
		{"plain header trimmed", map[string]string{HeaderJA4: "  b  "}, "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			if got := JA4FromHeaders(h); got != tt.want {
				t.Errorf("JA4FromHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}
