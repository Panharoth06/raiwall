package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/pkg/engine/ast"
	"github.com/Panharoth06/raiwall/pkg/engine/normalizer"
)

// SemanticOption allows customizing SemanticEngine settings.
type SemanticOption func(*SemanticEngine)

// WithASTTimeout sets the timeout for bounded AST verification per parameter.
func WithASTTimeout(d time.Duration) SemanticOption {
	return func(s *SemanticEngine) {
		if d > 0 {
			s.astTimeout = d
			s.sqlChop.Timeout = d
			s.cmdChop.Timeout = d
			s.xssChop.Timeout = d
		}
	}
}

// WithMaxParamSize sets the maximum parameter size for AST parsing before falling back to lexical triage.
func WithMaxParamSize(size int) SemanticOption {
	return func(s *SemanticEngine) {
		if size > 0 {
			s.maxParamSize = size
			s.sqlChop.MaxParamSize = size
			s.cmdChop.MaxParamSize = size
			s.xssChop.MaxParamSize = size
		}
	}
}

// SemanticEngine implements the WAFEngine interface with a three-stage funnel:
// Stage 1: Recursive normalization & structured parameter extraction
// Stage 2: Pure-Go lexical triage (< 2 µs)
// Stage 3: Bounded AST context verification (SQL, Shell, XSS) with 32 KB cap and 5 ms timeout.
type SemanticEngine struct {
	normalizer   *normalizer.Normalizer
	sqlChop      *ast.SQLChop
	cmdChop      *ast.CMDChop
	xssChop      *ast.XSSChop
	maxParamSize int
	astTimeout   time.Duration
}

// NewSemanticEngine creates an initialized SemanticEngine with production defaults.
func NewSemanticEngine(opts ...SemanticOption) *SemanticEngine {
	s := &SemanticEngine{
		normalizer:   normalizer.NewNormalizer(),
		sqlChop:      ast.NewSQLChop(),
		cmdChop:      ast.NewCMDChop(),
		xssChop:      ast.NewXSSChop(),
		maxParamSize: ast.DefaultMaxParamSize,
		astTimeout:   ast.DefaultASTTimeout,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the identifier for this engine.
func (s *SemanticEngine) Name() string {
	return "semantic"
}

// InspectRequest coordinates Stage 1 -> Stage 2 -> Stage 3 inspection across all parameters.
func (s *SemanticEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	if ctx == nil {
		return VerdictAllow, nil
	}

	reqCtx := ctx.Context
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	// Stage 1: Extract all parameters (Path, Query, Headers, JSON/Form/Multipart Body)
	params := normalizer.ExtractParameters(ctx.Path, ctx.Query, ctx.Headers, ctx.Body)
	if len(params) == 0 {
		return VerdictAllow, nil
	}

	var timeoutVerdict *Verdict

	for _, param := range params {
		if len(param.Value) == 0 {
			continue
		}

		// Stage 1: Multi-pass recursive normalization (stabilize within <= 10 iterations)
		normalized := s.normalizer.Normalize(param.Value)
		if len(normalized) == 0 {
			continue
		}

		// Stage 2: Fast Lexical Triage (<2 µs)
		triage, details := TriageWithDetails(normalized)
		if triage == TriageBenign {
			// Fast path: bypass Stage 3 AST parsing completely
			continue
		}

		// Enforce parameter size cap: if > maxParamSize, rely on Stage 2 lexical triage
		if len(normalized) > s.maxParamSize {
			ruleID := "LEXICAL_" + triage.String()
			return &Verdict{
				Action: ActionBlock,
				RuleID: ruleID,
				Reason: fmt.Sprintf("Threat detected in oversized parameter %s (%s): %s", param.Name, param.Location, details),
			}, nil
		}

		// Stage 3: Bounded AST Context Verification
		var astVerdict *ast.Verdict
		var err error

		switch triage {
		case TriageSuspectSQLi:
			astVerdict, err = s.sqlChop.Verify(reqCtx, normalized)
		case TriageSuspectCmdI:
			astVerdict, err = s.cmdChop.Verify(reqCtx, normalized)
		case TriageSuspectXSS:
			astVerdict, err = s.xssChop.Verify(reqCtx, normalized)
		}

		if err != nil {
			return nil, err
		}

		if astVerdict != nil {
			if astVerdict.Action == ast.ActionBlock {
				// Immediate short-circuit on confirmed threat
				return &Verdict{
					Action: ActionBlock,
					RuleID: astVerdict.RuleID,
					Reason: fmt.Sprintf("%s (param %q in %s)", astVerdict.Reason, param.Name, param.Location),
				}, nil
			} else if astVerdict.Action == ast.ActionAudit {
				if timeoutVerdict == nil {
					timeoutVerdict = &Verdict{
						Action: ActionAudit,
						RuleID: astVerdict.RuleID,
						Reason: fmt.Sprintf("%s (param %q in %s)", astVerdict.Reason, param.Name, param.Location),
					}
				}
			}
		}
	}

	if timeoutVerdict != nil {
		return timeoutVerdict, nil
	}

	return VerdictAllow, nil
}

// InspectResponse evaluates the response context (passthrough for request threat inspection).
func (s *SemanticEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	return VerdictAllow, nil
}
