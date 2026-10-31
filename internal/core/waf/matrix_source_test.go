package waf

import "testing"

func TestMatrixForApp_AllDisabledMatrixIsHonored(t *testing.T) {
	var allDisabled SemanticMatrix
	got := matrixForApp(StaticMatrixSource{Matrix: allDisabled}, "app-1")
	for i, mode := range got {
		if mode != ModeDisabled {
			t.Fatalf("module index %d = %v, want disabled (an all-disabled matrix must not fall back to defaults)", i, mode)
		}
	}
}
