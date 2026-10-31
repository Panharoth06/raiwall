package waf

import "testing"

type stubEngine struct {
	requestVerdict  *Verdict
	responseVerdict *Verdict
	requestCalled   *bool
}

func (s *stubEngine) InspectRequest(*RequestContext) (*Verdict, error) {
	if s.requestCalled != nil {
		*s.requestCalled = true
	}
	return s.requestVerdict, nil
}

func (s *stubEngine) InspectResponse(*ResponseContext) (*Verdict, error) {
	return s.responseVerdict, nil
}

func (s *stubEngine) Name() string { return "stub" }

func TestCompositeEngine_BlockWinsAndShortCircuits(t *testing.T) {
	called := false
	primary := &stubEngine{requestVerdict: &Verdict{Action: ActionBlock, RuleID: "SEMANTIC_XSS"}}
	secondary := &stubEngine{requestVerdict: VerdictAllow, requestCalled: &called}

	v, err := NewCompositeEngine(primary, secondary).InspectRequest(&RequestContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.RuleID != "SEMANTIC_XSS" {
		t.Fatalf("expected primary block, got %+v", v)
	}
	if called {
		t.Fatal("secondary engine ran after a primary block")
	}
}

func TestCompositeEngine_SecondaryBlocksWhenPrimaryAllows(t *testing.T) {
	primary := &stubEngine{requestVerdict: VerdictAllow}
	secondary := &stubEngine{requestVerdict: &Verdict{Action: ActionBlock, RuleID: "CRS_949110"}}

	v, err := NewCompositeEngine(primary, secondary).InspectRequest(&RequestContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Action != ActionBlock || v.RuleID != "CRS_949110" {
		t.Fatalf("expected CRS block, got %+v", v)
	}
}

func TestCompositeEngine_SurfacesAudit(t *testing.T) {
	primary := &stubEngine{requestVerdict: VerdictAllow}
	secondary := &stubEngine{requestVerdict: &Verdict{Action: ActionAudit, RuleID: "CRS_911100"}}

	v, err := NewCompositeEngine(primary, secondary).InspectRequest(&RequestContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Action != ActionAudit || v.RuleID != "CRS_911100" {
		t.Fatalf("expected audit verdict, got %+v", v)
	}
}

func TestCompositeEngine_BothAllow(t *testing.T) {
	v, err := NewCompositeEngine(
		&stubEngine{requestVerdict: VerdictAllow},
		&stubEngine{requestVerdict: VerdictAllow},
	).InspectRequest(&RequestContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Action != ActionAllow {
		t.Fatalf("expected allow, got %+v", v)
	}
}
