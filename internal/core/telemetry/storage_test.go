package telemetry

import (
	"reflect"
	"testing"
)

func TestSeveritiesAtLeast(t *testing.T) {
	cases := map[string][]string{
		"info":     {"info", "low", "medium", "high", "critical"},
		"MEDIUM":   {"medium", "high", "critical"},
		"critical": {"critical"},
		"bogus":    nil,
		"":         nil,
	}
	for in, want := range cases {
		if got := SeveritiesAtLeast(in); !reflect.DeepEqual(got, want) {
			t.Errorf("SeveritiesAtLeast(%q) = %v, want %v", in, got, want)
		}
	}
}
