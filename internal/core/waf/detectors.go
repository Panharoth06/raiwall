package waf

// DetectionLevel expresses the confidence of a semantic detector match.
type DetectionLevel int

// Detection confidence levels.
const (
	// LevelStrong is a confident signature match: block in Balance mode.
	LevelStrong DetectionLevel = 2
	// LevelWeak is a low-confidence heuristic hit: block only in Strict mode.
	LevelWeak DetectionLevel = 1
)

// Detection represents a semantic module lexical match.
type Detection struct {
	Module Module
	Level  DetectionLevel
	Reason string
	// Matched is the exact offending token snippet (for telemetry).
	Matched string
}

// scanSemanticModules evaluates the extended module detectors (code injection,
// deserialization, SSTI) over a normalized parameter value using pure lexical
// heuristics in < 2 µs. The first match wins; scanners order from cheapest
// fast-path prechecks to richest signatures.
func scanSemanticModules(v string) (Detection, bool) {
	if len(v) == 0 {
		return Detection{}, false
	}

	// 1. Serialization magic bytes (cheapest: fixed substrings)
	if d, ok := scanJavaDeser(v); ok {
		return d, true
	}
	if d, ok := scanPHPDeser(v); ok {
		return d, true
	}

	// 2. Code injection scanners
	if d, ok := scanJavaCodeInj(v); ok {
		return d, true
	}
	if d, ok := scanPHPCodeInj(v); ok {
		return d, true
	}
	if d, ok := scanASPCodeInj(v); ok {
		return d, true
	}
	if d, ok := scanSSTI(v); ok {
		return d, true
	}

	return Detection{}, false
}
