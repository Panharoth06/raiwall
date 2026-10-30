package waf

import (
	"context"

	"github.com/Panharoth06/raiwall/internal/core/waf/ast"
	"github.com/Panharoth06/raiwall/internal/core/waf/normalizer"
)

// triageCandidates normalizes a raw parameter value and returns every
// normalization variant plus the most suspicious candidate and its triage
// classification. Comment-obfuscated values produce two variants: one that
// reconstructs keywords split across comments (UN/**/ION) and one that
// preserves word boundaries (UNION/**/SELECT). Both must be triaged because
// each variant defeats a different obfuscation.
func triageCandidates(n *normalizer.Normalizer, raw string) (variants []string, chosen string, triage TriageResult, details string) {
	variants = n.NormalizeVariants(raw)
	for _, candidate := range variants {
		if len(candidate) == 0 {
			continue
		}
		if chosen == "" {
			chosen = candidate
		}
		if t, d := TriageWithDetails(candidate); t != TriageBenign {
			return variants, candidate, t, d
		}
	}
	return variants, chosen, TriageBenign, ""
}

// verifyHTMLFallback runs bounded HTML verification when a value triaged as
// SQLi also has markup shape. libinjection fingerprints payloads such as
// <iframe srcdoc="<script>..."> as SQL, which would otherwise leave an
// executable HTML payload verified only against SQL grammar. The result
// follows gateDetection semantics: (nil, false) not applicable or allowed;
// (verdict, true) record (audit) or return (block).
func (s *SemanticEngine) verifyHTMLFallback(
	matrix SemanticMatrix,
	ctx *RequestContext,
	reqCtx context.Context,
	param normalizer.Parameter,
	normalized string,
	triage TriageResult,
	details string,
) (*Verdict, bool) {
	if triage != TriageSuspectSQLi || !looksLikeHTMLInjection(normalized) {
		return nil, false
	}

	verdict, err := s.xssChop.Verify(reqCtx, normalized)
	if err != nil || verdict == nil || verdict.Action != ast.ActionBlock {
		return nil, false
	}

	det := Detection{
		Module:  ModuleXSS,
		Level:   LevelStrong,
		Reason:  verdict.Reason,
		Matched: details,
	}
	return s.gateDetection(matrix, ctx, det, verdict.RuleID, string(param.Location), param.Name)
}

// extendedModuleVerdict scans every normalization variant for Stage 2b module
// matches (code injection, deserialization, SSTI, uploads). The first handled
// result wins, matching scanSemanticModules ordering within a variant.
func extendedModuleVerdict(
	s *SemanticEngine,
	matrix SemanticMatrix,
	ctx *RequestContext,
	param normalizer.Parameter,
	variants []string,
) (*Verdict, bool) {
	for _, candidate := range variants {
		if len(candidate) == 0 {
			continue
		}
		if verdict, handled := s.inspectExtendedModule(matrix, ctx, param, candidate); handled {
			return verdict, true
		}
	}
	return nil, false
}
