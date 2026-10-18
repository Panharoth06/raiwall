package engine

import (
	"context"
	"net/http"
	"testing"
)

func BenchmarkBenignRequest(b *testing.B) {
	eng := NewSemanticEngine()
	ctx := &RequestContext{
		Method: "GET",
		Path:   "/api/v1/items",
		Query:  "page=2&limit=50&category=books&sort=price_asc",
		Headers: http.Header{
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
			"Accept":     []string{"application/json"},
			"Cookie":     []string{"sess=1234567890; pref=light"},
		},
		Body:    []byte(`{"filter": "paperback", "in_stock": true}`),
		Context: context.Background(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := eng.InspectRequest(ctx)
		if err != nil || verdict.Action != ActionAllow {
			b.Fatalf("unexpected benchmark failure: %v, %v", verdict, err)
		}
	}
}

func BenchmarkSuspectSQLi(b *testing.B) {
	eng := NewSemanticEngine()
	ctx := &RequestContext{
		Method:  "GET",
		Path:    "/users",
		Query:   "id=1'%20OR%20'1'='1",
		Context: context.Background(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := eng.InspectRequest(ctx)
		if err != nil || verdict.Action != ActionBlock {
			b.Fatalf("unexpected benchmark failure: %v, %v", verdict, err)
		}
	}
}

func BenchmarkSuspectCmdI(b *testing.B) {
	eng := NewSemanticEngine()
	ctx := &RequestContext{
		Method:  "GET",
		Path:    "/ping",
		Query:   "host=127.0.0.1;%20cat%20/etc/passwd",
		Context: context.Background(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := eng.InspectRequest(ctx)
		if err != nil || verdict.Action != ActionBlock {
			b.Fatalf("unexpected benchmark failure: %v, %v", verdict, err)
		}
	}
}

func BenchmarkSuspectXSS(b *testing.B) {
	eng := NewSemanticEngine()
	ctx := &RequestContext{
		Method:  "GET",
		Path:    "/search",
		Query:   "q=%3Cscript%3Ealert(1)%3C/script%3E",
		Context: context.Background(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		verdict, err := eng.InspectRequest(ctx)
		if err != nil || verdict.Action != ActionBlock {
			b.Fatalf("unexpected benchmark failure: %v, %v", verdict, err)
		}
	}
}

func BenchmarkLexicalTriage_Benign(b *testing.B) {
	val := "page=10&limit=50&sort=asc&query=machine_learning"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := Triage(val)
		if res != TriageBenign {
			b.Fatalf("expected benign, got %v", res)
		}
	}
}

func BenchmarkLexicalTriage_SQLi(b *testing.B) {
	val := "1' OR '1'='1"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := Triage(val)
		if res != TriageSuspectSQLi {
			b.Fatalf("expected suspect sqli, got %v", res)
		}
	}
}
