package waf

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf/ast"
	"github.com/Panharoth06/raiwall/internal/core/waf/normalizer"
)

// SemanticOption allows customizing SemanticEngine settings.
type SemanticOption func(*SemanticEngine)

// WithExceptionEngine configures an ExceptionMatcher (e.g. *acl.ExceptionEngine) on the SemanticEngine.
func WithExceptionEngine(matcher ExceptionMatcher) SemanticOption {
	return func(s *SemanticEngine) {
		s.exceptionMatcher = matcher
	}
}

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
	normalizer       *normalizer.Normalizer
	sqlChop          *ast.SQLChop
	cmdChop          *ast.CMDChop
	xssChop          *ast.XSSChop
	exceptionMatcher ExceptionMatcher
	matrixSource     MatrixSource
	maxParamSize     int
	astTimeout       time.Duration
}

// auditFinding collects the first audit-level finding across all parameters so
// it can be surfaced as an ActionAudit verdict when no blocking rule fires.
type auditFinding struct {
	verdict *Verdict
}

// SetExceptionEngine dynamically updates the ExceptionMatcher.
func (s *SemanticEngine) SetExceptionEngine(matcher ExceptionMatcher) {
	s.exceptionMatcher = matcher
}

// ExceptionEngine returns the active ExceptionMatcher.
func (s *SemanticEngine) ExceptionEngine() ExceptionMatcher {
	return s.exceptionMatcher
}

// WithMatrixSource configures the per-application semantic matrix resolver.
func WithMatrixSource(src MatrixSource) SemanticOption {
	return func(s *SemanticEngine) {
		if src != nil {
			s.matrixSource = src
		}
	}
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

// moduleForTriage maps a lexical triage classification to its semantic module.
func moduleForTriage(triage TriageResult) Module {
	switch triage {
	case TriageSuspectSQLi:
		return ModuleSQLInj
	case TriageSuspectXSS:
		return ModuleXSS
	case TriageSuspectCmdI:
		return ModuleCmdInj
	case TriageSuspectTraversal:
		return ModuleFileInclude
	default:
		return ""
	}
}

// lexicalRuleID returns the canonical RuleID prefix for a triage classification.
func lexicalRuleID(triage TriageResult) string {
	switch triage {
	case TriageSuspectSQLi:
		return "SEMANTIC_SQLI"
	case TriageSuspectXSS:
		return "SEMANTIC_XSS"
	case TriageSuspectCmdI:
		return "SEMANTIC_CMDI"
	case TriageSuspectTraversal:
		return "SEMANTIC_TRAVERSAL"
	default:
		return ""
	}
}

// lexicalBlockReason builds a deterministic human-readable block reason.
func lexicalBlockReason(triage TriageResult, details, paramName, location string) string {
	return fmt.Sprintf("%s detected in param %q (%s): %s", triageReasonLabel(triage), paramName, location, details)
}

// moduleRuleID returns the canonical verdict RuleID for an extended module detector.
func moduleRuleID(m Module) string {
	switch m {
	case ModuleFileUpload:
		return "SEMANTIC_FILE_UPLOAD"
	case ModuleJavaCodeInj:
		return "SEMANTIC_JAVA_CODE_INJ"
	case ModuleJavaDeser:
		return "SEMANTIC_JAVA_DESER"
	case ModulePHPDeser:
		return "SEMANTIC_PHP_DESER"
	case ModulePHPCodeInj:
		return "SEMANTIC_PHP_CODE_INJ"
	case ModuleASPCodeInj:
		return "SEMANTIC_ASP_CODE_INJ"
	case ModuleSSTI:
		return "SEMANTIC_SSTI"
	case ModuleSSRF:
		return "SEMANTIC_SSRF"
	case ModuleCSRF:
		return "SEMANTIC_CSRF"
	case ModuleMalHTTP:
		return "SEMANTIC_MAL_HTTP"
	default:
		return ""
	}
}

// inspectExtendedModule runs the Stage 2b lexical detectors over a value the
// main triage classified as benign and applies the matrix gating.
// Return values: (nil, false) no detector matched; (nil, true) match was
// suppressed (disabled module / tolerated weak heuristics / excepted rule);
// (verdict, true) the verdict should be recorded (audit) or returned (block).
func (s *SemanticEngine) inspectExtendedModule(
	matrix SemanticMatrix,
	ctx *RequestContext,
	param normalizer.Parameter,
	normalized string,
) (*Verdict, bool) {
	det, matched := scanSemanticModules(param.Name, normalized)
	if !matched {
		return nil, false
	}
	return s.gateDetection(matrix, ctx, det, moduleRuleID(det.Module), string(param.Location), param.Name)
}

// gateDetection applies semantic matrix gating to a detection. Return values
// follow inspectExtendedModule semantics: (nil, false) never; (nil, true)
// suppressed; (verdict, true) record (audit) or return (block).
func (s *SemanticEngine) gateDetection(
	matrix SemanticMatrix,
	ctx *RequestContext,
	det Detection,
	ruleID, location, paramName string,
) (*Verdict, bool) {
	mode := matrix.Mode(det.Module)
	switch mode {
	case ModeDisabled:
		return nil, true
	case ModeAudit:
		return &Verdict{
			Action:          ActionAudit,
			RuleID:          ruleID,
			Reason:          fmt.Sprintf("%s in param %q (%s): %s", det.Reason, paramName, location, det.Matched),
			AttackCategory:  string(det.Module),
			MatchedToken:    det.Matched,
			PayloadLocation: location,
		}, true
	}

	if s.excepted(ctx.Host, ctx.Path, ctx.Method, location, paramName, ruleID) {
		return nil, true
	}

	// Balance tolerates low-confidence heuristics; Strict enforces both levels.
	if det.Level == LevelWeak && mode == ModeBalance {
		return nil, true
	}

	return &Verdict{
		Action:          ActionBlock,
		RuleID:          ruleID,
		Reason:          fmt.Sprintf("%s in param %q (%s): %s", det.Reason, paramName, location, det.Matched),
		AttackCategory:  string(det.Module),
		MatchedToken:    det.Matched,
		PayloadLocation: location,
	}, true
}

func triageReasonLabel(triage TriageResult) string {
	switch triage {
	case TriageSuspectSQLi:
		return "SQL injection"
	case TriageSuspectXSS:
		return "Cross-site scripting"
	case TriageSuspectCmdI:
		return "Command injection"
	case TriageSuspectTraversal:
		return "Path traversal / LFI"
	default:
		return "Threat"
	}
}

// recordAudit stores the first audit-level finding. The verdict MUST already
// reflect its final audit form (never ActionBlock).
func (a *auditFinding) record(v *Verdict) {
	if a == nil || a.verdict != nil || v == nil {
		return
	}
	a.verdict = v
}

// downgradeToAudit converts a would-be block verdict into an audit-record verdict.
func downgradeToAudit(v *Verdict) *Verdict {
	if v == nil {
		return nil
	}
	down := *v
	down.Action = ActionAudit
	return &down
}

// excepted is a nil-safe wrapper over the exception matcher.
func (s *SemanticEngine) excepted(host, path, method, location, paramName, ruleID string) bool {
	if s.exceptionMatcher == nil {
		return false
	}
	return s.exceptionMatcher.Matches(host, path, method, location, paramName, ruleID)
}

// InspectRequest coordinates Stage 1 -> Stage 2 -> Stage 3 inspection across all parameters,
// gated by the per-application SemanticMatrix (Disabled/Audit/Balance/Strict per module).
func (s *SemanticEngine) InspectRequest(ctx *RequestContext) (*Verdict, error) {
	if ctx == nil {
		return VerdictAllow, nil
	}

	reqCtx := ctx.Context
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	// Resolve the effective per-application semantic matrix (hot path: single atomic read).
	matrix := matrixForApp(s.matrixSource, ctx.AppID)

	finding := &auditFinding{}

	// Stage 2a: request-level structural and contextual checks (malformed
	// HTTP smuggling markers and cross-origin validation). Audits are recorded
	// without preempting deeper parameter inspection.
	for _, rl := range requestLevelDetections(ctx) {
		verdict, controlled := s.gateDetection(matrix, ctx, rl.detection, moduleRuleID(rl.detection.Module), "Header", rl.paramName)
		if !controlled {
			continue
		}
		if verdict == nil {
			continue
		}
		if verdict.Action == ActionAudit {
			finding.record(verdict)
			continue
		}
		return verdict, nil
	}

	// Stage 1: Extract all parameters (Path, Query, Headers, JSON/Form/Multipart Body)
	params := normalizer.ExtractParameters(ctx.Path, ctx.Query, ctx.Headers, ctx.Body)
	if len(params) == 0 {
		return VerdictAllow, nil
	}

	for _, param := range params {
		if len(param.Value) == 0 {
			continue
		}

		// Exception Gate: check if this parameter is globally exempt from all rules (*)
		if s.excepted(ctx.Host, ctx.Path, ctx.Method, string(param.Location), param.Name, "*") {
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
			// Stage 2b: extended module detectors (code injection,
			// deserialization, SSTI) for values the main triage passed.
			verdict, handled := s.inspectExtendedModule(matrix, ctx, param, normalized)
			if !handled {
				continue
			}
			if verdict == nil {
				continue
			}
			if verdict.Action == ActionAudit {
				finding.record(verdict)
				continue
			}
			return verdict, nil
		}

		module := moduleForTriage(triage)
		mode := matrix.Mode(module)

		// Matrix gating: Disabled modules skip inspection entirely;
		// Audit modules record the detection without interrupting traffic.
		switch mode {
		case ModeDisabled:
			continue
		case ModeAudit:
			finding.record(&Verdict{
				Action:          ActionAudit,
				RuleID:          lexicalRuleID(triage),
				Reason:          lexicalBlockReason(triage, details, param.Name, string(param.Location)),
				AttackCategory:  string(module),
				MatchedToken:    details,
				PayloadLocation: string(param.Location),
			})
			continue
		}

		targetRuleID := lexicalRuleID(triage)

		// Exception Gate: skip if parameter is exempt from this threat category
		if s.excepted(ctx.Host, ctx.Path, ctx.Method, string(param.Location), param.Name, targetRuleID) {
			continue
		}

		// Enforce parameter size cap: if > maxParamSize, rely on Stage 2 lexical triage
		if len(normalized) > s.maxParamSize {
			ruleID := "LEXICAL_" + triage.String()
			if s.excepted(ctx.Host, ctx.Path, ctx.Method, string(param.Location), param.Name, ruleID) {
				continue
			}
			return &Verdict{
				Action:          ActionBlock,
				RuleID:          ruleID,
				Reason:          fmt.Sprintf("Threat detected in oversized parameter %s (%s): %s", param.Name, param.Location, details),
				AttackCategory:  string(module),
				MatchedToken:    details,
				PayloadLocation: string(param.Location),
			}, nil
		}

		// Strict modules enforce lower anomaly thresholds: block directly on the
		// lexical triage signal without waiting for bounded AST confirmation.
		if mode == ModeStrict {
			return &Verdict{
				Action:          ActionBlock,
				RuleID:          targetRuleID,
				Reason:          lexicalBlockReason(triage, details, param.Name, string(param.Location)),
				AttackCategory:  string(module),
				MatchedToken:    details,
				PayloadLocation: string(param.Location),
			}, nil
		}

		// Stage 3: Bounded Verification
		// Path Traversal / LFI is structural & deterministic
		if triage == TriageSuspectTraversal {
			return &Verdict{
				Action:          ActionBlock,
				RuleID:          targetRuleID,
				Reason:          lexicalBlockReason(triage, details, param.Name, string(param.Location)),
				AttackCategory:  string(module),
				MatchedToken:    details,
				PayloadLocation: string(param.Location),
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
				if s.excepted(ctx.Host, ctx.Path, ctx.Method, string(param.Location), param.Name, astVerdict.RuleID) {
					continue
				}
				return &Verdict{
					Action:          ActionBlock,
					RuleID:          astVerdict.RuleID,
					Reason:          fmt.Sprintf("%s (param %q in %s)", astVerdict.Reason, param.Name, param.Location),
					AttackCategory:  string(module),
					MatchedToken:    details,
					PayloadLocation: string(param.Location),
				}, nil
			} else if astVerdict.Action == ast.ActionAudit {
				if s.excepted(ctx.Host, ctx.Path, ctx.Method, string(param.Location), param.Name, astVerdict.RuleID) {
					continue
				}
				finding.record(&Verdict{
					Action:          ActionAudit,
					RuleID:          astVerdict.RuleID,
					Reason:          fmt.Sprintf("%s (param %q in %s)", astVerdict.Reason, param.Name, param.Location),
					AttackCategory:  string(module),
					MatchedToken:    details,
					PayloadLocation: string(param.Location),
				})
			}
		}
	}

	if finding.verdict != nil {
		return finding.verdict, nil
	}

	return VerdictAllow, nil
}

// InspectResponse evaluates the response context (passthrough for request threat inspection).
func (s *SemanticEngine) InspectResponse(ctx *ResponseContext) (*Verdict, error) {
	return VerdictAllow, nil
}
