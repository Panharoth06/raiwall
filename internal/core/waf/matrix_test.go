package waf

import (
	"encoding/json"
	"testing"
)

func TestDefaultMatrixAllBalance(t *testing.T) {
	m := DefaultMatrix()
	for _, meta := range ModuleRegistry {
		if m.Mode(meta.Module) != ModeBalance {
			t.Errorf("module %s: expected balance, got %s", meta.Module, m.Mode(meta.Module))
		}
	}
}

func TestModuleCountMatchesRegistry(t *testing.T) {
	if NumModules != len(ModuleRegistry) {
		t.Fatalf("NumModules=%d but ModuleRegistry has %d entries", NumModules, len(ModuleRegistry))
	}
	// Duplicate detection
	seen := make(map[Module]bool, NumModules)
	for _, meta := range ModuleRegistry {
		if seen[meta.Module] {
			t.Errorf("duplicate module %q in registry", meta.Module)
		}
		seen[meta.Module] = true
	}
	if len(seen) != NumModules {
		t.Fatalf("expected %d unique modules, got %d", NumModules, len(seen))
	}
}

func TestModuleIndex(t *testing.T) {
	if ModuleIndex(ModuleSQLInj) != 0 {
		t.Errorf("expected ModuleSQLInj index 0, got %d", ModuleIndex(ModuleSQLInj))
	}
	if ModuleIndex(ModuleMalHTTP) != NumModules-1 {
		t.Errorf("expected ModuleMalHTTP last index, got %d", ModuleIndex(ModuleMalHTTP))
	}
	if ModuleIndex(Module("missing")) != -1 {
		t.Errorf("expected -1 for unknown module")
	}
}

func TestIsKnownModule(t *testing.T) {
	t.Run("ValidModules", func(t *testing.T) {
		for _, meta := range ModuleRegistry {
			if !IsValidModule(meta.Module) {
				t.Errorf("expected %q to be a valid module", meta.Module)
			}
		}
	})

	t.Run("UnknownModule", func(t *testing.T) {
		if IsValidModule(Module(" VulcanExpr")) {
			t.Error("unknown module incorrectly accepted")
		}
	})
}

func TestApplyOverrides(t *testing.T) {
	base := DefaultMatrix()
	overridden := base.ApplyOverrides(map[Module]ModuleMode{
		ModuleSQLInj:      ModeStrict,
		ModuleXSS:         ModeDisabled,
		Module("unknown"): ModeAudit,
	})

	if overridden.Mode(ModuleSQLInj) != ModeStrict {
		t.Errorf("sql_inj: expected strict, got %s", overridden.Mode(ModuleSQLInj))
	}
	if overridden.Mode(ModuleXSS) != ModeDisabled {
		t.Errorf("xss: expected disabled, got %s", overridden.Mode(ModuleXSS))
	}
	if overridden.Mode(ModuleCmdInj) != ModeBalance {
		t.Errorf("cmd_inj: expected untouched balance, got %s", overridden.Mode(ModuleCmdInj))
	}

	// Base must remain untouched
	if base.Mode(ModuleSQLInj) != ModeBalance {
		t.Error("ApplyOverrides must not mutate the base matrix")
	}
}

func TestParseModuleModeString(t *testing.T) {
	valid := map[string]ModuleMode{
		"disabled": ModeDisabled,
		"audit":    ModeAudit,
		"balance":  ModeBalance,
		"strict":   ModeStrict,
	}
	for s, want := range valid {
		got, err := ParseModuleModeString(s)
		if err != nil {
			t.Errorf("ParseModuleModeString(%q): unexpected error %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("ParseModuleModeString(%q) = %s, want %s", s, got, want)
		}
	}
	if _, err := ParseModuleModeString("paranoid"); err == nil {
		t.Error("expected error for unknown mode string")
	}
}

func TestModuleModeJSONRoundTrip(t *testing.T) {
	type payload struct {
		Mode ModuleMode `json:"mode"`
	}

	for _, mode := range []ModuleMode{ModeDisabled, ModeAudit, ModeBalance, ModeStrict} {
		data, err := json.Marshal(payload{Mode: mode})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"mode":"` + mode.String() + `"}`
		if string(data) != want {
			t.Errorf("marshal(%s) = %s, want %s", mode, data, want)
		}
		var back payload
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if back.Mode != mode {
			t.Errorf("roundtrip mismatch: %s != %s", back.Mode, mode)
		}
	}
}

func TestModuleModeJSONLegacyOrdinal(t *testing.T) {
	var module struct {
		Mode ModuleMode `json:"mode"`
	}
	if err := json.Unmarshal([]byte(`{"mode":3}`), &module); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if module.Mode != ModeStrict {
		t.Errorf("expected strict from ordinal 3, got %s", module.Mode)
	}
}

func TestModuleModeJSONInvalid(t *testing.T) {
	var module struct {
		Mode ModuleMode `json:"mode"`
	}
	if err := json.Unmarshal([]byte(`{"mode":"paranoid"}`), &module); err == nil {
		t.Error("expected error for unknown mode string")
	}
	if err := json.Unmarshal([]byte(`{"mode":9}`), &module); err == nil {
		t.Error("expected error for out-of-range ordinal")
	}
}

func TestSemanticMatrixMapping(t *testing.T) {
	t.Run("IsDisabled", func(t *testing.T) {
		m := DefaultMatrix().ApplyOverrides(map[Module]ModuleMode{ModuleSSRF: ModeDisabled})
		if !m.IsDisabled(ModuleSSRF) || m.IsEnabled(ModuleSSRF) {
			t.Error("expected SSRF disabled")
		}
	})

	t.Run("IsAudit", func(t *testing.T) {
		m := DefaultMatrix().ApplyOverrides(map[Module]ModuleMode{ModuleSSTI: ModeAudit})
		if !m.IsAudit(ModuleSSTI) {
			t.Error("expected SSTI audit")
		}
	})

	t.Run("IsStrict", func(t *testing.T) {
		m := DefaultMatrix().ApplyOverrides(map[Module]ModuleMode{ModuleXSS: ModeStrict})
		if !m.IsStrict(ModuleXSS) {
			t.Error("expected XSS strict")
		}
	})
}

func TestStaticMatrixSource(t *testing.T) {
	src := StaticMatrixSource{Matrix: DefaultMatrix().ApplyOverrides(map[Module]ModuleMode{ModuleCSRF: ModeDisabled})}
	if got := src.MatrixFor("app-1"); got.Mode(ModuleCSRF) != ModeDisabled {
		t.Errorf("expected CSRF disabled, got %s", got.Mode(ModuleCSRF))
	}
}
