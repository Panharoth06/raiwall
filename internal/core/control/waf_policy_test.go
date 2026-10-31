package control_test

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestResolveWAFPolicyFor_Inheritance(t *testing.T) {
	app := &control.AppConfig{
		ID:        "app-1",
		Name:      "App",
		Hostnames: []string{"app.test"},
		Mode:      control.ModeDefense,
	}
	snap := control.NewConfigSnapshot(1, control.ModeDefense, []*control.AppConfig{app})
	snap.WAFPolicy = &control.WAFPolicySnapshot{
		DetectionMode: control.DetectionModeAlert,
		Sensitivity:   control.SensitivityHigh,
	}
	app.WAFPolicy = &control.WAFPolicySnapshot{DetectionMode: control.DetectionModeOff}

	resolved := snap.ResolveWAFPolicyFor("app-1")
	require.Equal(t, control.DetectionModeOff, resolved.DetectionMode)
	require.Equal(t, control.SensitivityHigh, resolved.Sensitivity)

	require.Equal(t, control.DetectionModeOff, snap.DetectionModeFor("app-1"))
	require.Equal(t, control.SensitivityHigh, snap.SensitivityFor("app-1"))
	require.Equal(t, control.DetectionModeAlert, snap.DetectionModeFor("missing"))
	require.Equal(t, control.SensitivityHigh, snap.SensitivityFor("missing"))
}

func TestSemanticMatrixFor_SensitivityPresets(t *testing.T) {
	app := &control.AppConfig{
		ID:        "app-1",
		Name:      "App",
		Hostnames: []string{"app.test"},
		Mode:      control.ModeDefense,
	}
	snap := control.NewConfigSnapshot(1, control.ModeDefense, []*control.AppConfig{app})

	snap.WAFPolicy = &control.WAFPolicySnapshot{Sensitivity: control.SensitivityHigh}
	high := snap.SemanticMatrixFor("app-1")
	require.Equal(t, waf.ModeStrict, high.Mode(waf.ModuleSQLInj))
	require.Equal(t, waf.ModeStrict, high.Mode(waf.ModuleXSS))

	snap.WAFPolicy = &control.WAFPolicySnapshot{Sensitivity: control.SensitivityLow}
	low := snap.SemanticMatrixFor("app-1")
	require.Equal(t, waf.ModeBalance, low.Mode(waf.ModuleSQLInj))
	require.Equal(t, waf.ModeAudit, low.Mode(waf.ModuleCSRF))
	require.Equal(t, waf.ModeAudit, low.Mode(waf.ModuleMalHTTP))

	// Explicit per-site module overrides still win over the preset.
	app.WAFPolicy = &control.WAFPolicySnapshot{
		SemanticOverrides: map[waf.Module]waf.ModuleMode{waf.ModuleSQLInj: waf.ModeAudit},
	}
	mixed := snap.SemanticMatrixFor("app-1")
	require.Equal(t, waf.ModeAudit, mixed.Mode(waf.ModuleSQLInj))
}

func TestSemanticMatrixFor_AllDisabledIsHonored(t *testing.T) {
	snap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	disabled := make(map[waf.Module]waf.ModuleMode, len(waf.ModuleRegistry))
	for _, meta := range waf.ModuleRegistry {
		disabled[meta.Module] = waf.ModeDisabled
	}
	snap.SemanticDefaults = disabled

	matrix := snap.SemanticMatrixFor("")
	for _, meta := range waf.ModuleRegistry {
		require.Equal(t, waf.ModeDisabled, matrix.Mode(meta.Module), "module %s", meta.Module)
	}
}
