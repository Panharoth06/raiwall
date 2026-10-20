package rate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
)

func BenchmarkGCRAThroughput(b *testing.B) {
	cfg := RateLimitConfig{
		Rate:   1000000,
		Period: time.Second,
		Burst:  100000,
	}

	storage := NewMemoryStorage()
	defer storage.Close()
	limiter := NewGCRALimiter(storage, cfg)
	defer limiter.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-ip-%d", i%1000)
			_, _ = limiter.Allow(ctx, key, 1)
			i++
		}
	})
}

func BenchmarkCompositeKeyBuilding(b *testing.B) {
	ip := net.ParseIP("203.0.113.195")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/resource", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "session-benchmark-token-xyz"})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = BuildCompositeKey(ip, ja4, req, "session")
		}
	})
}

func BenchmarkBanManagerFastPath(b *testing.B) {
	bm := NewBanManager(nil)
	defer bm.Close()

	ip := net.ParseIP("198.51.100.50")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"
	bm.Ban(ip, ja4, 1*time.Hour, "ddos_bot")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = bm.IsBanned(ip, ja4)
		}
	})
}

func BenchmarkTier1Enforce(b *testing.B) {
	pow := bot.NewPoWEngine(bot.PoWConfig{
		Secret:     "bench-pow-secret-32-bytes-long!!",
		Difficulty: 100,
	})

	limiter := NewTier1VelocityLimiter(Tier1Config{
		Rate:       1000000,
		Period:     time.Second,
		Burst:      500000,
		PoWEngine:  pow,
		CookieName: "session",
	})
	defer limiter.Close()

	ip := net.ParseIP("198.51.100.10")
	ja4 := "t13d1516h2_ja4"
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/test", nil)
	req.Header.Set("Accept", "application/json")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder()
		for pb.Next() {
			_, _ = limiter.Enforce(w, req, ip, ja4)
		}
	})
}
