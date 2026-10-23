package cve

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// rulesJSON is the compiled, embedded virtual-patch signature library.
//
//go:embed rules.json
var rulesJSON []byte

// NewBundled builds an engine around the embedded production signature set.
func NewBundled() (*Engine, error) {
	var rules []Signature
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("cve: parse bundled rules: %w", err)
	}
	return NewEngine(rules)
}

// BundledRules decodes the embedded signature library without building an
// engine (used by the control plane and API to enumerate rule metadata).
func BundledRules() ([]Signature, error) {
	var rules []Signature
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("cve: parse bundled rules: %w", err)
	}
	return rules, nil
}
