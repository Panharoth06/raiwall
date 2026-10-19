package telemetry

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkRingBuffer_SequentialPush(b *testing.B) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      100000,
		BatchSize:     1000,
		FlushInterval: 1 * time.Second,
		Handler: func(events []*ForensicEvent) error {
			return nil
		},
	})
	defer rb.Close()

	event := &ForensicEvent{
		EventID:    "bench-12345",
		Timestamp:  time.Now(),
		Host:       "example.com",
		Path:       "/api/v1/search?q=test",
		Method:     "GET",
		ClientIP:   "192.0.2.10",
		Action:     "allow",
		Severity:   "info",
		StatusCode: 200,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rb.Push(event)
	}
}

func BenchmarkRingBuffer_PushParallel(b *testing.B) {
	rb := NewRingBuffer(RingBufferConfig{
		Capacity:      200000,
		BatchSize:     2000,
		FlushInterval: 1 * time.Second,
		Handler: func(events []*ForensicEvent) error {
			return nil
		},
	})
	defer rb.Close()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		event := &ForensicEvent{
			EventID:    "bench-parallel",
			Timestamp:  time.Now(),
			Host:       "api.example.com",
			Path:       "/checkout",
			Method:     "POST",
			ClientIP:   "198.51.100.5",
			Action:     "allow",
			Severity:   "info",
			StatusCode: 200,
		}
		for pb.Next() {
			rb.Push(event)
		}
	})
}

func BenchmarkSanitizer_SanitizeEvent(b *testing.B) {
	sanitizer := NewSanitizer()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		event := &ForensicEvent{
			EventID:   "bench-sanitizer",
			Timestamp: time.Now(),
			Host:      "secure.example.com",
			Path:      "/api/login?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNxdACt7VICAcqAnDeoqQ50TC1NwafuvhSAsTvWA&password=SuperSecretPassword123!",
			Method:    "POST",
			ClientIP:  "203.0.113.50",
			Headers: map[string]string{
				"Authorization":   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNxdACt7VICAcqAnDeoqQ50TC1NwafuvhSAsTvWA",
				"X-Api-Key":       "sk_live_1234567890abcdef",
				"Cookie":          "session=abcd1234token; user=test",
				"X-Forwarded-For": "203.0.113.50",
			},
			TruncatedPayload: `{"card_number":"4532 0150 1234 5678","cvv":"123","password":"MySecretPassword"}`,
		}
		sanitizer.Sanitize(event)
	}
}

func BenchmarkSQLiteStore_SaveBatch(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "bench-sqlite.db")

	store, err := NewSQLiteStore(SQLiteConfig{
		DSN:       dbPath,
		Retention: 24 * time.Hour,
	})
	if err != nil {
		b.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Prepare a batch of 100 events
	const batchCount = 100
	events := make([]*ForensicEvent, batchCount)
	for i := 0; i < batchCount; i++ {
		events[i] = &ForensicEvent{
			EventID:    fmt.Sprintf("bench-evt-%d", i),
			Timestamp:  time.Now(),
			Host:       "bench.example.com",
			Path:       "/api/v1/test",
			Method:     "GET",
			ClientIP:   "192.0.2.1",
			Action:     "allow",
			Severity:   "info",
			StatusCode: 200,
			Latency:    150 * time.Microsecond,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := store.SaveBatch(ctx, events); err != nil {
			b.Fatalf("SaveBatch failed: %v", err)
		}
	}
}

func BenchmarkSQLiteStore_Query(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "bench-sqlite-query.db")

	store, err := NewSQLiteStore(SQLiteConfig{
		DSN:       dbPath,
		Retention: 24 * time.Hour,
	})
	if err != nil {
		b.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed 500 events
	events := make([]*ForensicEvent, 500)
	for i := 0; i < 500; i++ {
		events[i] = &ForensicEvent{
			EventID:    fmt.Sprintf("seed-%d", i),
			Timestamp:  time.Now(),
			Host:       "query.example.com",
			Path:       "/api/items",
			Method:     "GET",
			ClientIP:   "192.0.2.50",
			Action:     "allow",
			Severity:   "info",
			StatusCode: 200,
		}
	}
	_ = store.SaveBatch(ctx, events)

	params := QueryParams{
		Limit: 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := store.Query(ctx, params)
		if err != nil {
			b.Fatalf("Query failed: %v", err)
		}
	}
}
