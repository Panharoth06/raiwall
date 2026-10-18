package acl

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/expr-lang/expr/vm"
)

func BenchmarkBART_LookupIPv4(b *testing.B) {
	bt := NewBARTTable()
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			_ = bt.InsertCIDR(fmt.Sprintf("%d.%d.0.0/16", i, j), "bench_feed", "")
		}
	}
	targetIP := net.ParseIP("42.42.10.5")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !bt.Contains(targetIP) {
			b.Fatal("lookup failed")
		}
	}
}

func BenchmarkBART_LookupIPv6(b *testing.B) {
	bt := NewBARTTable()
	for i := 0; i < 1000; i++ {
		_ = bt.InsertCIDR(fmt.Sprintf("2001:db8:%x::/48", i), "bench_v6", "")
	}
	targetIP := net.ParseIP("2001:db8:42::1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !bt.Contains(targetIP) {
			b.Fatal("ipv6 lookup failed")
		}
	}
}

func BenchmarkBART_InFeed(b *testing.B) {
	bt := NewBARTTable()
	for i := 0; i < 1000; i++ {
		_ = bt.InsertCIDR(fmt.Sprintf("198.51.%d.0/24", i%256), "crowdsec", "")
	}
	targetIP := net.ParseIP("198.51.100.42")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !bt.InFeed(targetIP, "crowdsec") {
			b.Fatal("in_feed check failed")
		}
	}
}

func BenchmarkExceptionEngine_Match(b *testing.B) {
	rules := []*ExceptionRule{
		{
			ID:         "EX_1",
			Host:       "api.example.com",
			PathPrefix: "/api/v1/posts",
			Method:     "POST",
			Location:   "body",
			ParamName:  "markdown_content",
			RuleID:     "SEMANTIC_SQLI",
		},
		{
			ID:         "EX_2",
			Host:       "api.example.com",
			PathPrefix: "/api/v1/comments",
			Method:     "POST",
			Location:   "body",
			ParamName:  "comment_text",
			RuleID:     "SEMANTIC_XSS",
		},
		{
			ID:         "EX_3",
			Host:       "*.example.com",
			PathRegex:  `^/search/.*$`,
			Method:     "GET",
			Location:   "query",
			ParamName:  "q",
			RuleID:     "*",
		},
	}

	engine, err := NewExceptionEngine(rules...)
	if err != nil {
		b.Fatalf("NewExceptionEngine error: %v", err)
	}

	host := "api.example.com"
	path := "/api/v1/posts"
	method := "POST"
	location := "body"
	param := "markdown_content"
	ruleID := "SEMANTIC_SQLI"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !engine.Matches(host, path, method, location, param, ruleID) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkACLEngine_Evaluation(b *testing.B) {
	bartTable := NewBARTTable()
	_ = bartTable.InsertCIDR("10.0.0.0/8", "internal", "")
	_ = bartTable.InsertCIDR("198.51.100.0/24", "tor", "")

	rules := []*ACLRule{
		{
			Name:       "rule-1",
			Expression: `in_cidr(ip, "192.168.0.0/16")`,
			Action:     ActionAllow,
			Priority:   1,
		},
		{
			Name:       "rule-2",
			Expression: `in_feed(ip, "tor")`,
			Action:     ActionBlock,
			Priority:   2,
		},
		{
			Name:       "rule-3",
			Expression: `method == "GET" && has_prefix(path, "/api") && headers["authorization"] != ""`,
			Action:     ActionAllow,
			Priority:   3,
		},
	}

	engineInstance, err := NewACLEngine(bartTable, nil, rules...)
	if err != nil {
		b.Fatalf("NewACLEngine error: %v", err)
	}

	reqCtx := &engine.RequestContext{
		ClientIP: net.ParseIP("172.16.0.1"),
		Method:   "GET",
		Path:     "/api/v1/users",
		Headers: http.Header{
			"Authorization": []string{"Bearer valid-token"},
		},
	}
	geo := GeoData{Country: "US", ASN: 15169}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, err := engineInstance.Evaluate(reqCtx, geo)
		if err != nil || !v.Matched {
			b.Fatal("evaluation failed")
		}
	}
}

func BenchmarkACLEngine_DirectBytecode(b *testing.B) {
	rule := &ACLRule{
		Name:       "bench-rule",
		Expression: `method == "GET" && path startsWith "/api"`,
		Action:     ActionAllow,
	}
	if err := rule.Compile(nil); err != nil {
		b.Fatalf("Compile error: %v", err)
	}

	env := &EvalEnv{
		Method: "GET",
		Path:   "/api/v1/users",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := vm.Run(rule.compiled, env)
		if err != nil || out != true {
			b.Fatal("bytecode run failed")
		}
	}
}
