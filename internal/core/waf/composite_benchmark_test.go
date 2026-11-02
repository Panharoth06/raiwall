package waf_test

import (
	"bytes"
	"context"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
)

func make1KBRequestBody() []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"user_id":12345,"username":"test_user","action":"update_profile","details":{`)
	buf.WriteString(`"bio":"Software engineer building high performance web application firewalls and reverse proxies.",`)
	buf.WriteString(`"location":"San Francisco, CA","website":"https://example.com","interests":["security","networking","go","distributed-systems"],`)
	buf.WriteString(`"settings":{"notifications":true,"two_factor":true,"theme":"dark","language":"en-US"},`)
	buf.WriteString(`"padding":"`)
	padLen := 1024 - buf.Len() - 3
	if padLen > 0 {
		buf.Write(bytes.Repeat([]byte("A"), padLen))
	}
	buf.WriteString(`"}}`)
	return buf.Bytes()
}

func make1KBRequestContext() *waf.RequestContext {
	body := make1KBRequestBody()
	return &waf.RequestContext{
		Method: "POST",
		Path:   "/api/v1/users/profile",
		Query:  "dry_run=false&include_meta=true",
		Headers: http.Header{
			"Content-Type":    []string{"application/json"},
			"User-Agent":      []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
			"Accept":          []string{"application/json"},
			"Accept-Language": []string{"en-US,en;q=0.9"},
		},
		Body:        body,
		Context:     context.Background(),
	}
}

func mustInitCRSEngine(tb testing.TB, pl int) waf.WAFEnginePort {
	tb.Helper()
	eng, err := crs.New(crs.Config{
		Mode:              crs.ModeAudit,
		ParanoiaLevel:     pl,
		InboundThreshold:  crs.DefaultInboundThreshold,
		OutboundThreshold: crs.DefaultOutboundThreshold,
		MaxBodySize:       1024 * 1024,
	})
	if err != nil {
		tb.Fatalf("failed to initialize CRS PL%d engine: %v", pl, err)
	}
	return eng
}

func BenchmarkInspection_SemanticOnly_1KB(b *testing.B) {
	eng := waf.NewSemanticEngine()
	ctx := make1KBRequestContext()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := eng.InspectRequest(ctx)
		if err != nil || verdict == nil {
			b.Fatalf("inspection error: %v, verdict: %v", err, verdict)
		}
	}
}

func BenchmarkInspection_Composite_PL1_1KB(b *testing.B) {
	semantic := waf.NewSemanticEngine()
	crsEng := mustInitCRSEngine(b, 1)
	comp := waf.NewCompositeEngine(semantic, crsEng)
	ctx := make1KBRequestContext()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := comp.InspectRequest(ctx)
		if err != nil || verdict == nil {
			b.Fatalf("inspection error: %v, verdict: %v", err, verdict)
		}
	}
}

func BenchmarkInspection_Composite_PL2_1KB(b *testing.B) {
	semantic := waf.NewSemanticEngine()
	crsEng := mustInitCRSEngine(b, 2)
	comp := waf.NewCompositeEngine(semantic, crsEng)
	ctx := make1KBRequestContext()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := comp.InspectRequest(ctx)
		if err != nil || verdict == nil {
			b.Fatalf("inspection error: %v, verdict: %v", err, verdict)
		}
	}
}

func BenchmarkInspection_Composite_PL3_1KB(b *testing.B) {
	semantic := waf.NewSemanticEngine()
	crsEng := mustInitCRSEngine(b, 3)
	comp := waf.NewCompositeEngine(semantic, crsEng)
	ctx := make1KBRequestContext()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := comp.InspectRequest(ctx)
		if err != nil || verdict == nil {
			b.Fatalf("inspection error: %v, verdict: %v", err, verdict)
		}
	}
}

func BenchmarkInspection_Composite_PL4_1KB(b *testing.B) {
	semantic := waf.NewSemanticEngine()
	crsEng := mustInitCRSEngine(b, 4)
	comp := waf.NewCompositeEngine(semantic, crsEng)
	ctx := make1KBRequestContext()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := comp.InspectRequest(ctx)
		if err != nil || verdict == nil {
			b.Fatalf("inspection error: %v, verdict: %v", err, verdict)
		}
	}
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	idx := int(float64(len(d)-1) * p)
	return d[idx]
}

func TestCRS_PL1_IncrementalLatencyP99(t *testing.T) {
	semantic := waf.NewSemanticEngine()
	crsPL1 := mustInitCRSEngine(t, 1)
	compPL1 := waf.NewCompositeEngine(semantic, crsPL1)
	ctx := make1KBRequestContext()

	// Warm up
	for i := 0; i < 20; i++ {
		_, _ = semantic.InspectRequest(ctx)
		_, _ = compPL1.InspectRequest(ctx)
	}

	const samples = 200
	semanticDurs := make([]time.Duration, samples)
	compPL1Durs := make([]time.Duration, samples)

	for i := 0; i < samples; i++ {
		start := time.Now()
		v, err := semantic.InspectRequest(ctx)
		semanticDurs[i] = time.Since(start)
		if err != nil || v == nil {
			t.Fatalf("semantic run %d failed: %v", i, err)
		}
	}

	for i := 0; i < samples; i++ {
		start := time.Now()
		v, err := compPL1.InspectRequest(ctx)
		compPL1Durs[i] = time.Since(start)
		if err != nil || v == nil {
			t.Fatalf("composite PL1 run %d failed: %v", i, err)
		}
	}

	sort.Slice(semanticDurs, func(i, j int) bool { return semanticDurs[i] < semanticDurs[j] })
	sort.Slice(compPL1Durs, func(i, j int) bool { return compPL1Durs[i] < compPL1Durs[j] })

	semP50 := percentile(semanticDurs, 0.50)
	semP99 := percentile(semanticDurs, 0.99)
	pl1P50 := percentile(compPL1Durs, 0.50)
	pl1P99 := percentile(compPL1Durs, 0.99)

	var incrementalP99 time.Duration
	if pl1P99 > semP99 {
		incrementalP99 = pl1P99 - semP99
	}

	t.Logf("1 KB Body Latency Metrics:")
	t.Logf("  Semantic Only: p50=%v, p99=%v", semP50, semP99)
	t.Logf("  Composite PL1: p50=%v, p99=%v", pl1P50, pl1P99)
	t.Logf("  CRS PL1 Incremental p99: %v (gate ceiling: 10ms)", incrementalP99)

	if raceEnabled {
		t.Logf("Skipping strict latency ceiling assertions under -race detector")
		return
	}

	const semanticGateCeiling = 500 * time.Microsecond
	if semP99 > semanticGateCeiling {
		t.Errorf("Semantic only p99 %v exceeded %v gate ceiling", semP99, semanticGateCeiling)
	}

	const crsGateCeiling = 10 * time.Millisecond
	if incrementalP99 > crsGateCeiling {
		t.Errorf("CRS PL1 incremental p99 overhead %v exceeded %v gate ceiling", incrementalP99, crsGateCeiling)
	}
}
