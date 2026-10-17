package proxy

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		wantIP     string
	}{
		{
			name: "CF-Connecting-IP takes highest precedence",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.1",
				"X-Real-IP":        "198.51.100.2",
				"X-Forwarded-For":  "192.0.2.3, 10.0.0.1",
			},
			remoteAddr: "127.0.0.1:54321",
			wantIP:     "203.0.113.1",
		},
		{
			name: "X-Real-IP takes precedence over XFF",
			headers: map[string]string{
				"X-Real-IP":       "198.51.100.2",
				"X-Forwarded-For": "192.0.2.3, 10.0.0.1",
			},
			remoteAddr: "127.0.0.1:54321",
			wantIP:     "198.51.100.2",
		},
		{
			name: "XFF first valid IP selected",
			headers: map[string]string{
				"X-Forwarded-For": "192.0.2.3, 10.0.0.1, 172.16.0.1",
			},
			remoteAddr: "127.0.0.1:54321",
			wantIP:     "192.0.2.3",
		},
		{
			name: "XFF with spaces and empty tokens",
			headers: map[string]string{
				"X-Forwarded-For": "  ,  203.0.113.195  , 10.0.0.1",
			},
			remoteAddr: "127.0.0.1:54321",
			wantIP:     "203.0.113.195",
		},
		{
			name: "Fallback to RemoteAddr when headers absent",
			headers: map[string]string{},
			remoteAddr: "198.51.100.50:60000",
			wantIP:     "198.51.100.50",
		},
		{
			name: "IPv6 in CF-Connecting-IP",
			headers: map[string]string{
				"CF-Connecting-IP": "2001:db8::1",
			},
			remoteAddr: "[::1]:54321",
			wantIP:     "2001:db8::1",
		},
		{
			name: "IPv6 in RemoteAddr with bracket port",
			headers: map[string]string{},
			remoteAddr: "[2001:db8:85a3::8a2e:370:7334]:8080",
			wantIP:     "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name: "Invalid spoofed header ignored, falls back to RemoteAddr",
			headers: map[string]string{
				"CF-Connecting-IP": "malicious<script>",
				"X-Real-IP":        "999.999.999.999",
				"X-Forwarded-For":  "unknown, localhost",
			},
			remoteAddr: "192.168.1.100:44321",
			wantIP:     "192.168.1.100",
		},
		{
			name: "Empty request RemoteAddr",
			headers: map[string]string{},
			remoteAddr: "",
			wantIP:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := ExtractClientIP(req)
			if tt.wantIP == "" {
				if ip != nil {
					t.Fatalf("expected nil IP, got %v", ip)
				}
				return
			}

			if ip == nil {
				t.Fatalf("expected IP %s, got nil", tt.wantIP)
			}

			expected := net.ParseIP(tt.wantIP)
			if !ip.Equal(expected) {
				t.Errorf("ExtractClientIP() = %v, want %v", ip, expected)
			}
		})
	}
}

func TestContextClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	// Before injection, should extract from remote addr
	ipBefore := GetClientIP(req)
	if !ipBefore.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("expected 1.2.3.4, got %v", ipBefore)
	}

	// Injected context
	customIP := net.ParseIP("9.9.9.9")
	ctx := WithClientIP(req.Context(), customIP)
	reqWithCtx := req.WithContext(ctx)

	ipAfter := GetClientIP(reqWithCtx)
	if !ipAfter.Equal(customIP) {
		t.Errorf("expected injected IP 9.9.9.9, got %v", ipAfter)
	}

	// Nil request safety
	if GetClientIP(nil) != nil {
		t.Errorf("expected nil for nil request")
	}
}
