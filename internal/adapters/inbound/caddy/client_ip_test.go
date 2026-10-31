package caddy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP_DefaultIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.RemoteAddr = "198.51.100.50:60000"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	req.Header.Set("X-Real-IP", "203.0.113.2")
	req.Header.Set("X-Forwarded-For", "203.0.113.3, 10.0.0.1")

	if ip := ExtractClientIP(req); !ip.Equal(net.ParseIP("198.51.100.50")) {
		t.Fatalf("default source trusted a spoofed header: %v", ip)
	}
	if ip := ExtractClientIPWithSource(req, "remote"); !ip.Equal(net.ParseIP("198.51.100.50")) {
		t.Fatalf("remote source = %v, want socket address", ip)
	}
}

func TestExtractClientIP_ExplicitSources(t *testing.T) {
	tests := []struct {
		name   string
		source string
		header map[string]string
		want   string
	}{
		{
			name:   "xff selects leftmost",
			source: "xff",
			header: map[string]string{"X-Forwarded-For": "192.0.2.3, 10.0.0.1, 172.16.0.1"},
			want:   "192.0.2.3",
		},
		{
			name:   "header maps to xff",
			source: "header",
			header: map[string]string{"X-Forwarded-For": "  ,  203.0.113.195  , 10.0.0.1"},
			want:   "203.0.113.195",
		},
		{
			name:   "x-real-ip",
			source: "x-real-ip",
			header: map[string]string{"X-Real-IP": "198.51.100.2"},
			want:   "198.51.100.2",
		},
		{
			name:   "cf-connecting-ip ipv6",
			source: "cf-connecting-ip",
			header: map[string]string{"CF-Connecting-IP": "2001:db8::1"},
			want:   "2001:db8::1",
		},
		{
			name:   "custom header with port",
			source: "X-Client-IP",
			header: map[string]string{"X-Client-IP": "[2001:db8:85a3::8a2e:370:7334]:443"},
			want:   "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:   "invalid forwarded value falls back to socket",
			source: "xff",
			header: map[string]string{"X-Forwarded-For": "unknown, localhost"},
			want:   "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			req.RemoteAddr = "192.168.1.100:44321"
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			ip := ExtractClientIPWithSource(req, tt.source)
			if ip == nil || !ip.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("got %v, want %s", ip, tt.want)
			}
		})
	}
}

func TestExtractClientIP_TrustedProxies(t *testing.T) {
	newReq := func(remote string, xff string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		return req
	}

	trusted := []string{"10.0.0.0/8", "192.168.0.0/16"}

	t.Run("walks right to left past trusted hops", func(t *testing.T) {
		req := newReq("10.0.0.1:1234", "203.0.113.9, 10.0.0.2")
		ip := ExtractClientIPWithTrustedProxies(req, "xff", trusted)
		if !ip.Equal(net.ParseIP("203.0.113.9")) {
			t.Fatalf("got %v, want 203.0.113.9", ip)
		}
	})

	t.Run("untrusted peer cannot assert a header", func(t *testing.T) {
		req := newReq("203.0.113.50:1234", "10.0.0.1")
		ip := ExtractClientIPWithTrustedProxies(req, "xff", trusted)
		if !ip.Equal(net.ParseIP("203.0.113.50")) {
			t.Fatalf("got %v, want direct peer", ip)
		}
	})

	t.Run("all hops trusted falls back to leftmost", func(t *testing.T) {
		req := newReq("10.0.0.1:1234", "10.0.0.2, 10.0.0.3")
		ip := ExtractClientIPWithTrustedProxies(req, "xff", trusted)
		if !ip.Equal(net.ParseIP("10.0.0.2")) {
			t.Fatalf("got %v, want 10.0.0.2", ip)
		}
	})
}

func TestContextClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	if ipBefore := GetClientIP(req); !ipBefore.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("expected 1.2.3.4, got %v", ipBefore)
	}

	customIP := net.ParseIP("9.9.9.9")
	ctx := WithClientIP(req.Context(), customIP)
	reqWithCtx := req.WithContext(ctx)

	if ipAfter := GetClientIP(reqWithCtx); !ipAfter.Equal(customIP) {
		t.Errorf("expected injected IP 9.9.9.9, got %v", ipAfter)
	}

	if GetClientIP(nil) != nil {
		t.Errorf("expected nil for nil request")
	}
	if ExtractClientIP(nil) != nil {
		t.Errorf("expected nil for ExtractClientIP(nil)")
	}
}
