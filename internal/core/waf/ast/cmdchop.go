package ast

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CMDChop performs bounded AST context verification for Command Injection.
type CMDChop struct {
	MaxParamSize   int
	Timeout        time.Duration
	AllowRedirects bool // Whether > or < alone are permissible (e.g. search filters)
}

// NewCMDChop creates a new CMDChop verifier with default production constraints.
func NewCMDChop() *CMDChop {
	return &CMDChop{
		MaxParamSize:   DefaultMaxParamSize,
		Timeout:        DefaultASTTimeout,
		AllowRedirects: false,
	}
}

// Verify evaluates candidate input against synthetic POSIX shell grammar contexts.
// Returns a Verdict indicating whether semantic breakout or execution occurred, or if timeout was reached.
func (c *CMDChop) Verify(ctx context.Context, input string) (*Verdict, error) {
	// 1. Enforce hard 32 KB parameter cap
	maxSize := c.MaxParamSize
	if maxSize <= 0 {
		maxSize = DefaultMaxParamSize
	}
	if len(input) > maxSize {
		return VerdictAllow, nil
	}

	// 2. Enforce 5 ms execution deadline
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultASTTimeout
	}
	evalCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		verdict *Verdict
		err     error
	}
	resChan := make(chan result, 1)

	go func() {
		v, err := c.probe(input)
		resChan <- result{verdict: v, err: err}
	}()

	select {
	case <-evalCtx.Done():
		if evalCtx.Err() == context.DeadlineExceeded {
			return &Verdict{
				Action: ActionAudit,
				RuleID: "PARSER_TIMEOUT",
				Reason: "Shell AST parser execution deadline exceeded",
			}, nil
		}
		return VerdictAllow, evalCtx.Err()
	case res := <-resChan:
		return res.verdict, res.err
	}
}

// probe performs multi-context synthetic POSIX shell grammar probing:
// Context 1: Unquoted argument: cmd <INPUT>
// Context 2: Double-quoted argument: cmd "<INPUT>"
// Context 3: Single-quoted argument: cmd '<INPUT>'
func (c *CMDChop) probe(input string) (*Verdict, error) {
	if len(input) == 0 {
		return VerdictAllow, nil
	}

	// 1. Immediate command substitution check: $(...) or `...` inside any context
	if hasSubst, subReason := checkSubstitutions(input); hasSubst {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_CMDI",
			Reason: fmt.Sprintf("Command injection detected via %s", subReason),
		}, nil
	}

	// 2. Context 1: Unquoted context (cmd <INPUT>)
	unquotedProbe := "cmd " + input
	if breakout, reason := analyzeShellAST(unquotedProbe, c.AllowRedirects); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_CMDI",
			Reason: fmt.Sprintf("Command injection detected via unquoted shell breakout: %s", reason),
		}, nil
	}

	// 3. Context 2: Double-quoted context (cmd "<INPUT>")
	doubleQuotedProbe := "cmd \"" + input + "\""
	if breakout, reason := analyzeQuotedShellAST(doubleQuotedProbe, '"'); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_CMDI",
			Reason: fmt.Sprintf("Command injection detected via double-quote shell breakout: %s", reason),
		}, nil
	}

	// 4. Context 3: Single-quoted context (cmd '<INPUT>')
	singleQuotedProbe := "cmd '" + input + "'"
	if breakout, reason := analyzeQuotedShellAST(singleQuotedProbe, '\''); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_CMDI",
			Reason: fmt.Sprintf("Command injection detected via single-quote shell breakout: %s", reason),
		}, nil
	}

	return VerdictAllow, nil
}

// checkSubstitutions detects command substitutions $(...) or backticks `...`
func checkSubstitutions(s string) (bool, string) {
	if strings.Contains(s, "$(") {
		if idx := strings.Index(s, "$("); idx != -1 {
			if strings.Contains(s[idx+2:], ")") {
				return true, "command substitution $(...)"
			}
		}
	}
	if strings.Contains(s, "`") {
		first := strings.IndexByte(s, '`')
		if first != -1 {
			if strings.Contains(s[first+1:], "`") {
				return true, "backtick execution `...`"
			}
			return true, "unbalanced backtick shell breakout"
		}
	}
	return false, ""
}
