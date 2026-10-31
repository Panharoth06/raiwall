package control

import (
	"fmt"
	"strings"
	"time"
)

// Detection rule sources.
const (
	RuleSourceSemantic = "semantic"
	RuleSourceCVE      = "cve"
	RuleSourceCRS      = "crs"
	RuleSourcePack     = "pack"
)

// Rule pack types.
const (
	PackTypeNative = "native"
	PackTypeModsec = "modsec"
	PackTypeCRS    = "crs"
)

// Rule pack relation to the embedded CRS ruleset.
const (
	PackRelationAdditive = "additive"
	PackRelationReplace  = "replace"
)

// Detection policy scopes.
const (
	PolicyScopeGlobal = "global"
	PolicyScopeApp    = "app"
)

// Detection modes.
const (
	DetectionModeInherit = "inherit"
	DetectionModeOff     = "off"
	DetectionModeAlert   = "alert"
	DetectionModeBlock   = "block"
)

// Detection sensitivity presets.
const (
	SensitivityInherit = "inherit"
	SensitivityLow     = "low"
	SensitivityMedium  = "medium"
	SensitivityHigh    = "high"
)

// Per-rule action overrides.
const (
	RuleActionInherit = "inherit"
	RuleActionBlock   = "block"
	RuleActionAlert   = "alert"
	RuleActionOff     = "off"
)

// Rule severities.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Catalog limits protect the control plane and snapshots from oversized packs.
const (
	MaxRulePacks  = 100
	MaxPackFiles  = 32
	MaxPackBytes  = 2 << 20
	MaxPackRules  = 20000
	MaxPackNameLn = 128
)

// RulePackRecord is the persisted form of an imported rule pack.
type RulePackRecord struct {
	ID             string
	Name           string
	Version        string
	Type           string
	Priority       int
	Enabled        bool
	ReplaceBuiltin bool
	RulesJSON      string
	Directives     string
	FilesJSON      string
	Checksum       string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RuleOverrideRecord is the persisted per-rule override.
type RuleOverrideRecord struct {
	CanonicalID string
	Enabled     *bool
	Severity    string
	Action      string
	UpdatedBy   string
	UpdatedAt   time.Time
}

// WAFPolicyRecord is the persisted global or per-site detection policy.
type WAFPolicyRecord struct {
	ID                   string
	Scope                string
	AppID                string
	DetectionMode        string
	Sensitivity          string
	SemanticOverrides    string
	CRSEnabled           *bool
	CRSParanoiaLevel     *int
	CRSInboundThreshold  *int
	CRSOutboundThreshold *int
	DisabledPackIDs      string
	UpdatedAt            time.Time
}

// CanonicalRuleID builds the stable catalog identifier for a rule.
func CanonicalRuleID(source, id string) string {
	return source + ":" + id
}

// ParseCanonicalRuleID splits a catalog identifier into source and rule ID.
func ParseCanonicalRuleID(canonical string) (source, id string, err error) {
	source, id, ok := strings.Cut(canonical, ":")
	if !ok || source == "" || id == "" {
		return "", "", fmt.Errorf("invalid canonical rule id %q", canonical)
	}
	switch source {
	case RuleSourceSemantic, RuleSourceCVE, RuleSourceCRS, RuleSourcePack:
		return source, id, nil
	default:
		return "", "", fmt.Errorf("unknown rule source %q in %q", source, canonical)
	}
}

// IsValidRuleSource reports whether source is a known catalog source.
func IsValidRuleSource(source string) bool {
	switch source {
	case RuleSourceSemantic, RuleSourceCVE, RuleSourceCRS, RuleSourcePack:
		return true
	default:
		return false
	}
}

// IsValidPackType reports whether t is a supported imported pack type.
func IsValidPackType(t string) bool {
	switch t {
	case PackTypeNative, PackTypeModsec, PackTypeCRS:
		return true
	default:
		return false
	}
}

// IsValidPackRelation reports whether relation is additive or replace.
func IsValidPackRelation(relation string) bool {
	return relation == PackRelationAdditive || relation == PackRelationReplace
}

// IsValidDetectionMode reports whether mode is a supported detection mode.
func IsValidDetectionMode(mode string) bool {
	switch mode {
	case DetectionModeInherit, DetectionModeOff, DetectionModeAlert, DetectionModeBlock:
		return true
	default:
		return false
	}
}

// IsValidSensitivity reports whether sensitivity is a supported preset.
func IsValidSensitivity(sensitivity string) bool {
	switch sensitivity {
	case SensitivityInherit, SensitivityLow, SensitivityMedium, SensitivityHigh:
		return true
	default:
		return false
	}
}

// IsValidRuleAction reports whether action is a supported rule override.
func IsValidRuleAction(action string) bool {
	switch action {
	case "", RuleActionInherit, RuleActionBlock, RuleActionAlert, RuleActionOff:
		return true
	default:
		return false
	}
}

// IsValidSeverity reports whether severity is a supported catalog severity.
func IsValidSeverity(severity string) bool {
	switch severity {
	case "", SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// NormalizePolicyValue converts "inherit" and whitespace to an empty value.
func NormalizePolicyValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "inherit" {
		return ""
	}
	return value
}
