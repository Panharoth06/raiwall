package acl

import (
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/expr-lang/expr/vm"
)

func BenchmarkACLExpr(b *testing.B) {
	rule := &ACLRule{
		Name:       "bench-rule",
		Expression: `method == "GET" && has_prefix(path, "/api") && headers["authorization"] != ""`,
		Action:     ActionAllow,
		Priority:   1,
	}
	aclEngine, err := NewACLEngine(nil, nil, rule)
	if err != nil {
		b.Fatalf("NewACLEngine error: %v", err)
	}

	reqCtx := &waf.RequestContext{
		Method: "GET",
		Path:   "/api/v1/resource",
		Headers: http.Header{
			"Authorization": []string{"Bearer token123"},
			"User-Agent":    []string{"Go-bench"},
		},
	}
	geo := GeoData{Country: "US", ASN: 15169}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, err := aclEngine.Evaluate(reqCtx, geo)
		if err != nil || !v.Matched {
			b.Fatal("benchmark evaluation failed")
		}
	}
}

func BenchmarkACLExpr_RawBytecode(b *testing.B) {
	rule := &ACLRule{
		Name:       "bench-rule",
		Expression: `method == "GET" && has_prefix(path, "/api") && headers["authorization"] != ""`,
		Action:     ActionAllow,
		Priority:   1,
	}
	if err := rule.Compile(nil); err != nil {
		b.Fatalf("Compile error: %v", err)
	}

	env := &EvalEnv{
		Method: "GET",
		Path:   "/api/v1/resource",
		Headers: map[string]string{
			"authorization": "Bearer token123",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := vm.Run(rule.compiled, env)
		if err != nil || out != true {
			b.Fatal("benchmark evaluation failed")
		}
	}
}

func BenchmarkPureBytecode(b *testing.B) {
	rule := &ACLRule{
		Name:       "bench-rule",
		Expression: `method == "GET" && has_prefix(path, "/api")`,
		Action:     ActionAllow,
	}
	_ = rule.Compile(nil)
	env := &EvalEnv{
		Method: "GET",
		Path:   "/api/v1/resource",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = vm.Run(rule.compiled, env)
	}
}

func BenchmarkPureBytecode_NativeOps(b *testing.B) {
	rule := &ACLRule{
		Name:       "bench-rule",
		Expression: `method == "GET" && path startsWith "/api"`,
		Action:     ActionAllow,
	}
	_ = rule.Compile(nil)
	env := &EvalEnv{
		Method: "GET",
		Path:   "/api/v1/resource",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = vm.Run(rule.compiled, env)
	}
}
