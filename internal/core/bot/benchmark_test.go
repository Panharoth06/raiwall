package bot

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkRouteClassification(b *testing.B) {
	classifier := NewRouteClassifier(nil)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer jwt-token-benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		route := classifier.Classify(req)
		if route != RouteAPI {
			b.Fatal("unexpected route")
		}
	}
}

func BenchmarkBotClassification(b *testing.B) {
	classifier := NewBotClassifier()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	ja4 := "t13d1516h2_normal_browser_hash"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict := classifier.Classify(req, ja4)
		if verdict.IsBot {
			b.Fatal("unexpected bot classification")
		}
	}
}

func BenchmarkBotClassification_Spoofed(b *testing.B) {
	classifier := NewBotClassifier()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	ja4 := "t13d1516h2_curl_default"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict := classifier.Classify(req, ja4)
		if !verdict.IsSpoofed {
			b.Fatal("expected spoofed classification")
		}
	}
}

func BenchmarkClearanceTokenValidation(b *testing.B) {
	cm := NewClearanceManager(ClearanceConfig{
		Secret: "benchmark-secret-key-clearance-32b",
		TTL:    2 * time.Hour,
	}, nil)

	ip := net.ParseIP("192.168.1.100")
	ja4 := "t13d1516h2_benchmark"
	token := cm.GenerateToken(ip, ja4, time.Now().Add(2*time.Hour))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !cm.ValidateToken(token, ip, ja4) {
			b.Fatal("token validation failed")
		}
	}
}

func BenchmarkHoneypotInjection_StaticHTML(b *testing.B) {
	injector := NewHoneypotInjector(DefaultTrapPath)
	html := []byte(`<!DOCTYPE html><html><head><title>Static Site</title></head><body><h1>Content</h1><p>Description</p></body></html>`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, ok := injector.Inject(html)
		if !ok {
			b.Fatal("injection failed")
		}
	}
}

func BenchmarkHoneypotInjection_SPAHydrationBypass(b *testing.B) {
	injector := NewHoneypotInjector(DefaultTrapPath)
	html := []byte(`<!DOCTYPE html><html><head><title>Next.js SPA</title></head><body><div id="__next"><div>Content</div></div></body></html>`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, ok := injector.Inject(html)
		if ok {
			b.Fatal("expected injection to be bypassed for SPA")
		}
	}
}

func BenchmarkHTTP2Fingerprint_ParseAndCompute(b *testing.B) {
	raw := "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fp, err := ParseH2Fingerprint(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = ComputeH2Hash(fp)
	}
}
