package control

import "testing"

func TestNormalizeSSLMode(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: SSLModeNone},
		{in: "none", want: SSLModeNone},
		{in: "AUTO", want: SSLModeAuto},
		{in: " manual ", want: SSLModeManual},
		{in: "on", wantErr: true},
	}
	for _, tc := range cases {
		got, err := NormalizeSSLMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeSSLMode(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeSSLMode(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("NormalizeSSLMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeRoutingType(t *testing.T) {
	cases := map[string]string{
		"":          RoutingProxy,
		"proxy":     RoutingProxy,
		"STATIC":    RoutingStatic,
		" redirect": RoutingRedirect,
	}
	for in, want := range cases {
		got, err := NormalizeRoutingType(in)
		if err != nil {
			t.Fatalf("NormalizeRoutingType(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("NormalizeRoutingType(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeRoutingType("tunnel"); err == nil {
		t.Error("expected error for unknown routing type")
	}
}

func TestNormalizeLoadBalancing(t *testing.T) {
	cases := map[string]string{
		"":               LoadBalanceRoundRobin,
		"round_robin":    LoadBalanceRoundRobin,
		"least_conn":     LoadBalanceLeastConn,
		"IP_HASH":        LoadBalanceIPHash,
		"primary_backup": LoadBalancePrimaryBackup,
	}
	for in, want := range cases {
		got, err := NormalizeLoadBalancing(in)
		if err != nil {
			t.Fatalf("NormalizeLoadBalancing(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("NormalizeLoadBalancing(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeLoadBalancing("random"); err == nil {
		t.Error("expected error for unknown balancing policy")
	}
}

func TestNormalizePorts(t *testing.T) {
	got, err := NormalizePorts(nil)
	if err != nil {
		t.Fatalf("NormalizePorts(nil): %v", err)
	}
	if len(got) != 1 || got[0].Port != 80 || got[0].Scheme != "http" {
		t.Fatalf("unexpected default ports: %+v", got)
	}

	got, err = NormalizePorts([]ListeningPort{{Port: 443, Scheme: "HTTPS"}, {Port: 8080, Scheme: ""}})
	if err != nil {
		t.Fatalf("NormalizePorts: %v", err)
	}
	if got[0].Scheme != "https" || got[1].Scheme != "http" {
		t.Errorf("schemes not normalized: %+v", got)
	}

	invalid := [][]ListeningPort{
		{{Port: 0, Scheme: "http"}},
		{{Port: 70000, Scheme: "http"}},
		{{Port: 80, Scheme: "tcp"}},
		{{Port: 80, Scheme: "http"}, {Port: 80, Scheme: "https"}},
	}
	for _, ports := range invalid {
		if _, err := NormalizePorts(ports); err == nil {
			t.Errorf("expected error for ports %+v", ports)
		}
	}
}

func TestHasHTTPSPort(t *testing.T) {
	if HasHTTPSPort([]ListeningPort{{Port: 80, Scheme: "http"}}) {
		t.Error("http-only ports reported https")
	}
	if !HasHTTPSPort([]ListeningPort{{Port: 80, Scheme: "http"}, {Port: 443, Scheme: "https"}}) {
		t.Error("expected https port to be detected")
	}
}

func TestIsValidRedirectTarget(t *testing.T) {
	valid := []string{"/", "/login", "https://example.com", "http://example.com/path?q=1"}
	for _, target := range valid {
		if !IsValidRedirectTarget(target) {
			t.Errorf("expected %q to be a valid redirect target", target)
		}
	}
	invalid := []string{"", "   ", "//example.com", "ftp://example.com", "example.com"}
	for _, target := range invalid {
		if IsValidRedirectTarget(target) {
			t.Errorf("expected %q to be rejected", target)
		}
	}
}

func TestIsValidRedirectStatus(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		if !IsValidRedirectStatus(status) {
			t.Errorf("expected %d to be valid", status)
		}
	}
	for _, status := range []int{0, 200, 303, 404} {
		if IsValidRedirectStatus(status) {
			t.Errorf("expected %d to be rejected", status)
		}
	}
}
