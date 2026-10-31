package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

type packValidationResult struct {
	Valid       bool     `json:"valid"`
	RulesParsed int      `json:"rules_parsed"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

func validateRulePack(payload rulePackPayload) packValidationResult {
	result := packValidationResult{Valid: true, RulesParsed: len(payload.Rules)}
	fail := func(format string, args ...any) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf(format, args...))
	}
	if strings.TrimSpace(payload.Name) == "" {
		fail("pack name is required")
	} else if len(payload.Name) > control.MaxPackNameLn {
		fail("pack name exceeds %d characters", control.MaxPackNameLn)
	}
	if payload.Type == "" {
		payload.Type = control.PackTypeNative
	}
	if !control.IsValidPackType(payload.Type) {
		fail("unknown pack type %q (expected native, modsec, or crs)", payload.Type)
	}
	if payload.Relation == "" {
		payload.Relation = control.PackRelationAdditive
	}
	if !control.IsValidPackRelation(payload.Relation) {
		fail("unknown relation %q (expected additive or replace)", payload.Relation)
	}
	if payload.Relation == control.PackRelationReplace && payload.Type != control.PackTypeCRS {
		fail("only crs packs may replace the embedded ruleset")
	}
	size := len(payload.Directives)
	for _, content := range payload.Files {
		size += len(content)
	}
	if len(payload.Files) > control.MaxPackFiles {
		fail("%d files exceeds the %d-file limit", len(payload.Files), control.MaxPackFiles)
	}
	if size > control.MaxPackBytes {
		fail("pack payload exceeds the %d-byte limit", control.MaxPackBytes)
	}

	switch payload.Type {
	case control.PackTypeNative:
		if len(payload.Rules) == 0 {
			fail("native pack contains no rules")
		}
		if len(payload.Rules) > control.MaxPackRules {
			fail("%d rules exceeds the %d-rule limit", len(payload.Rules), control.MaxPackRules)
		}
		if len(payload.Rules) > 0 {
			if _, err := cve.NewEngine(payload.Rules); err != nil {
				fail("%v", err)
			}
		}
	case control.PackTypeModsec, control.PackTypeCRS:
		if strings.TrimSpace(payload.Directives) == "" && !hasConfContent(payload.Files) {
			fail("pack contains no directive text or .conf file")
		}
		conf := crs.Config{
			Mode:          crs.ModeAudit,
			MaxBodySize:   crs.DefaultMaxBodySize,
			ParanoiaLevel: crs.DefaultParanoiaLevel,
			Packs: []crs.Pack{{
				ID:             "validate",
				ReplaceBuiltin: payload.Relation == control.PackRelationReplace,
				Directives:     payload.Directives,
				Files:          payload.Files,
			}},
		}
		if _, err := crs.New(conf); err != nil {
			fail("%v", err)
		}
		filesJSON, _ := json.Marshal(payload.Files)
		result.RulesParsed = countModsecRules(payload.Directives, string(filesJSON))
	}
	return result
}

func hasConfContent(files map[string]string) bool {
	for name := range files {
		if strings.HasSuffix(strings.ToLower(name), ".conf") {
			return true
		}
	}
	return false
}

func normalizePackPriority(priority int) int {
	if priority <= 0 {
		return 100
	}
	return priority
}

func countModsecRules(directives, filesJSON string) int {
	count := len(crs.ScanDirectiveMetadata(directives))
	if filesJSON != "" && filesJSON != "{}" {
		var files map[string]string
		if err := json.Unmarshal([]byte(filesJSON), &files); err == nil {
			for name, content := range files {
				if strings.HasSuffix(strings.ToLower(name), ".conf") {
					count += len(crs.ScanDirectiveMetadata(content))
				}
			}
		}
	}
	return count
}

func decodeNativeRuleCount(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	var rules []cve.Signature
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return 0, err
	}
	return len(rules), nil
}
