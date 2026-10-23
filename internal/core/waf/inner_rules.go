package waf

import (
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
)

// WithInnerRules attaches the virtual-patching engine. Inner rules are hard,
// binary exploit signatures: an enabled signature blocks on first match,
// ahead of the triage funnel and independent of the semantic matrix.
func WithInnerRules(e *cve.Engine) SemanticOption {
	return func(s *SemanticEngine) {
		s.innerRules = e
	}
}

// SetInnerRules swaps the virtual-patching engine at runtime.
func (s *SemanticEngine) SetInnerRules(e *cve.Engine) {
	s.innerRules = e
}

// locationFor maps a detection surface to a verdict PayloadLocation.
func locationFor(field, header string) string {
	switch field {
	case cve.FieldPath:
		return "Path"
	case cve.FieldQuery:
		return "Query"
	case cve.FieldBody:
		return "Body"
	case cve.FieldHeader:
		return header
	default:
		return "Request"
	}
}

// inspectInnerRules runs Stage 0: virtual-patch signature evaluation.
// (nil, false): no signature fired; (nil, true): engine disabled; verdict: block.
func (s *SemanticEngine) inspectInnerRules(ctx *RequestContext) (*Verdict, bool) {
	if s.innerRules == nil {
		return nil, false
	}

	match, fired := s.innerRules.Evaluate(&cve.Input{
		Method:   ctx.Method,
		Path:     cve.DecodePath(ctx.Path),
		RawQuery: ctx.Query,
		Headers:  ctx.Headers,
		Body:     ctx.Body,
	})
	if !fired {
		return nil, false
	}

	return &Verdict{
		Action:          ActionBlock,
		RuleID:          match.Rule.ID,
		Reason:          fmt.Sprintf("Virtual patch %s: %s (matched %s %q)", match.Rule.ID, match.Rule.Name, locationFor(match.Field, match.Header), match.Token),
		AttackCategory:  "cve/" + match.Category,
		MatchedToken:    match.Token,
		PayloadLocation: locationFor(match.Field, match.Header),
	}, true
}
