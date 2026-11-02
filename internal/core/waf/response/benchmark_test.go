package response

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func generate1MiBPayload(panCount int) []byte {
	var buf bytes.Buffer
	buf.WriteString("{\"status\":\"ok\",\"records\":[")
	for i := 0; i < panCount; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("{\"id\":")
		buf.WriteString(fmt.Sprintf("%d", i))
		buf.WriteString(",\"name\":\"Customer Name\",\"card\":\"4111 1111 1111 1111\",\"api_key\":\"1234567890abcdef\",\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\",\"note\":\"regular customer\"}")
	}
	buf.WriteString("],\"padding\":\"")
	// Pad up to 1 MiB
	target := 1024 * 1024
	current := buf.Len()
	if current < target-2 {
		padding := bytes.Repeat([]byte("A"), target-current-2)
		buf.Write(padding)
	}
	buf.WriteString("\"}")
	return buf.Bytes()
}

func BenchmarkDLP_1MiBScan(b *testing.B) {
	eng, err := New(Config{
		Enabled:     true,
		Mode:        string(ModeAudit),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:           true,
			Action:            string(ModeAudit),
			DetectPAN:         true,
			DetectSecrets:     true,
			DetectJWT:         true,
			DetectPrivateKeys: true,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      1024 * 1024,
		},
	})
	if err != nil {
		b.Fatalf("failed to init engine: %v", err)
	}

	payload := generate1MiBPayload(10)
	ctx := &waf.ResponseContext{
		StatusCode:  200,
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        payload,
		Context:     context.Background(),
		ContentType: "application/json",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := eng.Inspect(ctx)
		if res == nil || len(res.Findings) == 0 {
			b.Fatalf("expected findings in 1MiB payload")
		}
	}
}

func BenchmarkDLP_PAN_Only(b *testing.B) {
	eng, _ := New(Config{
		Enabled:     true,
		Mode:        string(ModeAudit),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:      true,
			DetectPAN:    true,
			MaxScanBytes: 1024 * 1024,
		},
	})
	payload := generate1MiBPayload(10)
	ctx := &waf.ResponseContext{
		StatusCode:  200,
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        payload,
		Context:     context.Background(),
		ContentType: "application/json",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Inspect(ctx)
	}
}

func BenchmarkDLP_Secret_Only(b *testing.B) {
	eng, _ := New(Config{
		Enabled:     true,
		Mode:        string(ModeAudit),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:       true,
			DetectSecrets: true,
			MaxScanBytes:  1024 * 1024,
		},
	})
	payload := generate1MiBPayload(10)
	ctx := &waf.ResponseContext{
		StatusCode:  200,
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        payload,
		Context:     context.Background(),
		ContentType: "application/json",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Inspect(ctx)
	}
}

func BenchmarkDLP_JWT_Only(b *testing.B) {
	eng, _ := New(Config{
		Enabled:     true,
		Mode:        string(ModeAudit),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:      true,
			DetectJWT:    true,
			MaxScanBytes: 1024 * 1024,
		},
	})
	payload := generate1MiBPayload(10)
	ctx := &waf.ResponseContext{
		StatusCode:  200,
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        payload,
		Context:     context.Background(),
		ContentType: "application/json",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Inspect(ctx)
	}
}

func TestDLP_1MiBLatencyP99(t *testing.T) {
	eng, err := New(Config{
		Enabled:     true,
		Mode:        string(ModeAudit),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:           true,
			Action:            string(ModeAudit),
			DetectPAN:         true,
			DetectSecrets:     true,
			DetectJWT:         true,
			DetectPrivateKeys: true,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      1024 * 1024,
		},
	})
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	payload := generate1MiBPayload(5)
	ctx := &waf.ResponseContext{
		StatusCode:  200,
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        payload,
		Context:     context.Background(),
		ContentType: "application/json",
	}

	// Warmup
	for i := 0; i < 5; i++ {
		_ = eng.Inspect(ctx)
	}

	// Sample 100 runs to calculate p99
	const runs = 100
	durations := make([]time.Duration, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()
		res := eng.Inspect(ctx)
		durations[i] = time.Since(start)
		if res == nil || len(res.Findings) == 0 {
			t.Fatalf("run %d: expected findings", i)
		}
	}

	// Simple sort to find p99 (index 98 in sorted 100)
	for i := 0; i < runs; i++ {
		for j := i + 1; j < runs; j++ {
			if durations[i] > durations[j] {
				durations[i], durations[j] = durations[j], durations[i]
			}
		}
	}
	p99 := durations[runs-2] // 99th percentile

	t.Logf("1 MiB DLP scan p99 latency: %v (gate ceiling: 25ms)", p99)
	if raceEnabled {
		t.Logf("Skipping strict 25ms latency ceiling assertion under -race detector")
		return
	}
	if p99 > 25*time.Millisecond {
		t.Errorf("1 MiB DLP scan p99 latency %v exceeded 25ms gate ceiling", p99)
	}
}

func TestDLP_Concurrent100Requests(t *testing.T) {
	eng, err := New(Config{
		Enabled:     true,
		Mode:        string(ModeRedact),
		InspectBody: true,
		BodyLimit:   1024 * 1024,
		DLP: DLPConfig{
			Enabled:           true,
			Action:            string(ModeRedact),
			DetectPAN:         true,
			DetectSecrets:     true,
			DetectJWT:         true,
			DetectPrivateKeys: true,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      1024 * 1024,
		},
	})
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	payload := generate1MiBPayload(5)

	const concurrency = 100
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx := &waf.ResponseContext{
				StatusCode:  200,
				Headers:     http.Header{"Content-Type": []string{"application/json"}},
				Body:        payload,
				Context:     context.Background(),
				ContentType: "application/json",
			}
			res := eng.Inspect(ctx)
			if res == nil || !res.Redacted || len(res.Body) == 0 {
				truncated := false
				redacted := false
				findings := 0
				bodyLen := 0
				if res != nil {
					truncated = res.Truncated
					redacted = res.Redacted
					findings = len(res.Findings)
					bodyLen = len(res.Body)
				}
				errCh <- fmt.Errorf("worker %d: res(truncated=%v, redacted=%v, findings=%d, bodyLen=%d)", id, truncated, redacted, findings, bodyLen)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent test failure: %v", err)
	}
}
