package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a YAML-friendly time.Duration. Values are written as human
// readable strings ("5ms", "2h", "720h") so the same file is portable between
// Docker Compose, Helm values, and bare-metal deployments.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a string such as \"5ms\" or \"2h\"")
	}

	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string such as \"5ms\" or \"2h\": %w", err)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler so exported configuration stays readable.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Std returns the equivalent time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// IsZero reports whether the duration is unset.
func (d Duration) IsZero() bool {
	return d == 0
}
