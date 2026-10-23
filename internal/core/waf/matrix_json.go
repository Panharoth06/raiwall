package waf

import (
	"encoding/json"
	"fmt"
)

// marshalSimpleString encodes a plain string as a JSON string literal.
func marshalSimpleString(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte(`""`), nil
	}
	return json.Marshal(s)
}

// unmarshalModuleMode decodes a ModuleMode from a JSON string name or numeric ordinal.
func unmarshalModuleMode(data []byte) (ModuleMode, error) {
	// Numeric ordinals (legacy snapshot compatibility)
	if len(data) > 0 && data[0] >= '0' && data[0] <= '9' {
		var ordinal uint8
		for _, c := range data {
			if c < '0' || c > '9' {
				return ModeDisabled, fmt.Errorf("invalid numeric mode value: %s", data)
			}
			ordinal = ordinal*10 + (c - '0')
			if ordinal > 3 {
				return ModeDisabled, fmt.Errorf("mode ordinal %d out of range 0-3", ordinal)
			}
		}
		return ModuleMode(ordinal), nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return ModeDisabled, fmt.Errorf("invalid mode: %s (expected string)", data)
	}
	switch s {
	case "disabled":
		return ModeDisabled, nil
	case "audit":
		return ModeAudit, nil
	case "balance":
		return ModeBalance, nil
	case "strict":
		return ModeStrict, nil
	default:
		return ModeDisabled, fmt.Errorf("unknown module mode %q", s)
	}
}
