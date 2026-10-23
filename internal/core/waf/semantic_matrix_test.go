package waf

import (
	"strings"
	"testing"
)

func matrixEngine(t *testing.T, overrides map[Module]ModuleMode) *SemanticEngine {
	t.Helper()
	return NewSemanticEngine(
		WithMatrixSource(StaticMatrixSource{Matrix: DefaultMatrix().ApplyOverrides(overrides)}),
	)
}

func sqliRequest(host string) *RequestContext {
	return &RequestContext{
		ClientIP: nil,
		Method:   "POST",
		Host:     host,
		Path:     "/login",
		Query:    "user=' OR 1=1--&pass=x",
		Body:     []byte(`{"q": "1' UNION SELECT password FROM users--"}`),
	}
}

func TestInspectBalanceModeBlocksSQLi(t *testing.T) {
	engine := matrixEngine(t, nil)

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected block verdict in balance mode, got %s (%s)", verdict.Action, verdict.Reason)
	}
	if verdict.RuleID == "" {
		t.Error("expected non-empty rule ID")
	}
	if verdict.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestInspectDisabledModuleSkips(t *testing.T) {
	engine := matrixEngine(t, map[Module]ModuleMode{
		ModuleSQLInj:      ModeDisabled,
		ModuleXSS:         ModeDisabled,
		ModuleCmdInj:      ModeDisabled,
		ModuleFileInclude: ModeDisabled,
	})

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Fatalf("expected allow when all relevant modules are disabled, got %s (%s)", verdict.Action, verdict.Reason)
	}
}

func TestInspectAuditModeDowngradesToAudit(t *testing.T) {
	engine := matrixEngine(t, map[Module]ModuleMode{
		ModuleSQLInj:      ModeAudit,
		ModuleXSS:         ModeAudit,
		ModuleCmdInj:      ModeAudit,
		ModuleFileInclude: ModeAudit,
	})

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionAudit {
		t.Fatalf("expected audit verdict in audit mode, got %s (%s)", verdict.Action, verdict.Reason)
	}
	if verdict.RuleID == "" || verdict.Reason == "" {
		t.Error("audit verdict must retain rule ID and reason")
	}
}

func TestInspectStrictModeBlocksOnLexicalSignal(t *testing.T) {
	engine := matrixEngine(t, map[Module]ModuleMode{ModuleSQLInj: ModeStrict})

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected block verdict in strict mode, got %s (%s)", verdict.Action, verdict.Reason)
	}
}

func TestInspectStrictModeBlocksWeakSignal(t *testing.T) {
	// A weak SQLi-ish signal that Balance mode tolerates via AST confirmation.
	engine := matrixEngine(t, map[Module]ModuleMode{ModuleXSS: ModeStrict})

	ctx := &RequestContext{
		Method: "GET",
		Host:   "example.test",
		Path:   "/search",
		Query:  "q=<img src=x onerror=alert(1)>",
	}
	verdict, err := engine.InspectRequest(ctx)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected strict block, got %s (%s)", verdict.Action, verdict.Reason)
	}
}

func TestInspectDefaultMatrixPreservesBaseline(t *testing.T) {
	engine := NewSemanticEngine()

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected default matrix to preserve SQLi blocking, got %s (%s)", verdict.Action, verdict.Reason)
	}

	// Benign traffic must pass untouched
	benign := &RequestContext{
		Method: "GET",
		Host:   "example.test",
		Path:   "/health",
		Query:  "user=john",
	}
	verdict, err = engine.InspectRequest(benign)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Errorf("benign traffic must be allowed, got %s (%s)", verdict.Action, verdict.Reason)
	}
}

func TestInspectVerdictCarriesTelemetryMetadata(t *testing.T) {
	engine := matrixEngine(t, nil)

	verdict, err := engine.InspectRequest(sqliRequest("example.test"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected block, got %s", verdict.Action)
	}
	if verdict.AttackCategory == "" {
		t.Error("expected AttackCategory populated")
	} else if !strings.Contains(verdict.AttackCategory, "sql") && !strings.Contains(verdict.AttackCategory, "inj") {
		t.Errorf("unexpected attack category %q", verdict.AttackCategory)
	}
	if verdict.PayloadLocation == "" {
		t.Error("expected PayloadLocation populated")
	}
}

func TestInspectPerAppPolicyOverridesGlobal(t *testing.T) {
	type appOverrideSource struct {
		overrides map[string]SemanticMatrix
	}
	src := appOverrideSource{
		overrides: map[string]SemanticMatrix{
			"strict-app":   DefaultMatrix(),
			"business-app": DefaultMatrix().ApplyOverrides(map[Module]ModuleMode{ModuleSQLInj: ModeAudit, ModuleXSS: ModeDisabled}),
		},
	}
	engine := NewSemanticEngine(WithMatrixSource(matrixFuncSrc(func(appID string) SemanticMatrix {
		if m, ok := src.overrides[appID]; ok {
			return m
		}
		return DefaultMatrix()
	})))

	// Business app: SQLi downgraded to audit even though global runs balance
	verdict, err := engine.InspectRequest(withAppID(sqliRequest("business.test"), "business-app"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionAudit {
		t.Fatalf("expected per-app audit policy, got %s (%s)", verdict.Action, verdict.Reason)
	}

	// Strict app still blocks
	verdict, err = engine.InspectRequest(withAppID(sqliRequest("strict.test"), "strict-app"))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected strict app to block, got %s (%s)", verdict.Action, verdict.Reason)
	}
}

func withAppID(ctx *RequestContext, appID string) *RequestContext {
	ctx.AppID = appID
	return ctx
}

func matrixFuncSrc(fn func(appID string) SemanticMatrix) MatrixSource {
	return matrixFunc(fn)
}

type matrixFunc func(appID string) SemanticMatrix

func (f matrixFunc) MatrixFor(appID string) SemanticMatrix { return f(appID) }
