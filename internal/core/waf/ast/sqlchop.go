package ast

import (
	"context"
	"fmt"
	"time"
)

// Default limits for AST context verification
const (
	DefaultMaxParamSize = 32 * 1024            // 32 KB cap
	DefaultASTTimeout   = 5 * time.Millisecond // 5 ms execution deadline
)

// SQLChop performs bounded AST context verification for SQL injection using multi-context synthetic probing.
type SQLChop struct {
	MaxParamSize int
	Timeout      time.Duration
}

// NewSQLChop creates a new SQLChop verifier with default production constraints.
func NewSQLChop() *SQLChop {
	return &SQLChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      DefaultASTTimeout,
	}
}

// Verify evaluates candidate input against synthetic SQL grammar contexts.
// Returns a Verdict indicating whether semantic breakout occurred, or if timeout was reached.
func (s *SQLChop) Verify(ctx context.Context, input string) (*Verdict, error) {
	// 1. Enforce hard 32 KB parameter cap
	maxSize := s.MaxParamSize
	if maxSize <= 0 {
		maxSize = DefaultMaxParamSize
	}
	if len(input) > maxSize {
		// Parameter exceeds cap: skip AST verification (rely on lexical triage)
		return VerdictAllow, nil
	}

	// 2. Enforce 5 ms execution deadline
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultASTTimeout
	}
	evalCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Channel for receiving evaluation outcome
	type result struct {
		verdict *Verdict
		err     error
	}
	resChan := make(chan result, 1)

	go func() {
		v, err := s.probe(input)
		resChan <- result{verdict: v, err: err}
	}()

	select {
	case <-evalCtx.Done():
		if evalCtx.Err() == context.DeadlineExceeded {
			// Downgrade timeout to ActionAudit with PARSER_TIMEOUT
			return &Verdict{
				Action: ActionAudit,
				RuleID: "PARSER_TIMEOUT",
				Reason: "SQL AST parser execution deadline exceeded",
			}, nil
		}
		return VerdictAllow, evalCtx.Err()
	case res := <-resChan:
		return res.verdict, res.err
	}
}

// probe performs multi-context synthetic grammar probing:
// Context 1: Quoted string literal: SELECT * FROM t WHERE c = '<INPUT>'
// Context 2: Unquoted literal/expression: SELECT * FROM t WHERE c = <INPUT>
func (s *SQLChop) probe(input string) (*Verdict, error) {
	if len(input) == 0 {
		return VerdictAllow, nil
	}

	// 1. Quoted string context probe
	// An input intended for a quoted string should remain strictly inside a single string literal node.
	quotedProbe := "SELECT * FROM t WHERE c = '" + input + "'"
	if breakout, reason := analyzeSQLQuotedBreakout(quotedProbe); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_SQLI",
			Reason: fmt.Sprintf("SQL injection detected via quoted context breakout: %s", reason),
		}, nil
	}

	// 2. Unquoted context probe (e.g. numeric IDs, ORDER BY clauses, expressions)
	unquotedProbe := "SELECT * FROM t WHERE c = " + input
	if breakout, reason := analyzeSQLUnquotedBreakout(unquotedProbe); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_SQLI",
			Reason: fmt.Sprintf("SQL injection detected via unquoted context breakout: %s", reason),
		}, nil
	}

	return VerdictAllow, nil
}
