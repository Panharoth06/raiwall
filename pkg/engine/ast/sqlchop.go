package ast

import (
	"context"
	"fmt"
	"strings"
	"time"

)

// Default limits for AST context verification
const (
	DefaultMaxParamSize = 32 * 1024        // 32 KB cap
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

// SQLTokenType represents categorized lexical tokens.
type SQLTokenType int

const (
	tokenEOF SQLTokenType = iota
	tokenWord
	tokenString
	tokenNumber
	tokenSymbol
	tokenComment
)

type sqlToken struct {
	typ SQLTokenType
	val string
}

// tokenizeSQL produces a stream of SQL tokens from a query string.
func tokenizeSQL(sql string) []sqlToken {
	var tokens []sqlToken
	i := 0
	n := len(sql)

	for i < n {
		b := sql[i]

		// Whitespace
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			i++
			continue
		}

		// Comments: -- or # or /* ... */
		if (b == '-' && i+1 < n && sql[i+1] == '-') || b == '#' {
			start := i
			for i < n && sql[i] != '\n' && sql[i] != '\r' {
				i++
			}
			tokens = append(tokens, sqlToken{typ: tokenComment, val: sql[start:i]})
			continue
		}
		if b == '/' && i+1 < n && sql[i+1] == '*' {
			start := i
			i += 2
			for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			}
			tokens = append(tokens, sqlToken{typ: tokenComment, val: sql[start:i]})
			continue
		}

		// Strings: '...' or "..."
		if b == '\'' || b == '"' {
			quote := b
			start := i
			i++
			for i < n {
				if sql[i] == quote {
					if i+1 < n && sql[i+1] == quote {
						// Escaped quote ('')
						i += 2
						continue
					}
					i++
					break
				}
				if sql[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			tokens = append(tokens, sqlToken{typ: tokenString, val: sql[start:i]})
			continue
		}

		// Numbers: [0-9]+
		if b >= '0' && b <= '9' {
			start := i
			for i < n && ((sql[i] >= '0' && sql[i] <= '9') || sql[i] == '.' || sql[i] == 'x' || sql[i] == 'X') {
				i++
			}
			tokens = append(tokens, sqlToken{typ: tokenNumber, val: sql[start:i]})
			continue
		}

		// Word / Identifiers / Keywords: [a-zA-Z_][a-zA-Z0-9_]*
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' {
			start := i
			for i < n && ((sql[i] >= 'a' && sql[i] <= 'z') || (sql[i] >= 'A' && sql[i] <= 'Z') ||
				(sql[i] >= '0' && sql[i] <= '9') || sql[i] == '_') {
				i++
			}
			tokens = append(tokens, sqlToken{typ: tokenWord, val: sql[start:i]})
			continue
		}

		// Symbols: =, ;, (, ), ,, +, -, *, etc.
		tokens = append(tokens, sqlToken{typ: tokenSymbol, val: string(b)})
		i++
	}

	return tokens
}

// analyzeSQLQuotedBreakout checks if the synthetic query SELECT * FROM t WHERE c = '<INPUT>'
// broke out of the string literal node.
func analyzeSQLQuotedBreakout(query string) (bool, string) {
	tokens := tokenizeSQL(query)

	// In a normal SELECT * FROM t WHERE c = '<INPUT>', the tokens are:
	// [SELECT] [*] [FROM] [t] [WHERE] [c] [=] [STRING_LITERAL]
	// Any tokens after the string literal indicate breakout!

	// Find the '=' token in WHERE clause
	eqIdx := -1
	for idx, tok := range tokens {
		if tok.val == "=" {
			eqIdx = idx
			break
		}
	}
	if eqIdx == -1 || eqIdx+1 >= len(tokens) {
		return false, ""
	}

	// Next token must be a string literal
	firstAfterEq := tokens[eqIdx+1]
	if firstAfterEq.typ != tokenString {
		// If not even a string literal, quote was broken immediately
		return true, "syntax escaped quoted string literal"
	}

	// Check tokens following the string literal
	remaining := tokens[eqIdx+2:]
	if len(remaining) == 0 {
		// Cleanly closed single string literal without extra tokens!
		return false, ""
	}

	// If there are tokens after the string literal:
	for _, tok := range remaining {
		upper := strings.ToUpper(tok.val)

		// Stacked queries
		if tok.val == ";" {
			return true, "stacked query delimiter (;)"
		}
		// Comment breakout (e.g. admin' --)
		if tok.typ == tokenComment {
			return true, "trailing comment injection (" + tok.val + ")"
		}
		// Logical operator breakout (e.g. ' OR 1=1)
		if upper == "OR" || upper == "AND" || upper == "XOR" {
			return true, "logical boolean breakout operator (" + upper + ")"
		}
		// Set operation breakout (e.g. ' UNION SELECT ...)
		if upper == "UNION" {
			return true, "set operation breakout (UNION)"
		}
		// Clause breakout
		if upper == "GROUP" || upper == "HAVING" || upper == "ORDER" || upper == "LIMIT" {
			return true, "SQL clause breakout (" + upper + ")"
		}
		// Attack functions
		if upper == "SLEEP" || upper == "BENCHMARK" || upper == "PG_SLEEP" || upper == "WAITFOR" {
			return true, "SQL time-delay function injection (" + upper + ")"
		}
	}

	return true, "unexpected tokens following string literal boundary"
}

// analyzeSQLUnquotedBreakout checks if input in an unquoted position introduces
// dangerous SQL constructs (e.g. UNION, stacked queries, boolean tautologies, comments).
func analyzeSQLUnquotedBreakout(query string) (bool, string) {
	tokens := tokenizeSQL(query)

	eqIdx := -1
	for idx, tok := range tokens {
		if tok.val == "=" {
			eqIdx = idx
			break
		}
	}
	if eqIdx == -1 || eqIdx+1 >= len(tokens) {
		return false, ""
	}

	afterEq := tokens[eqIdx+1:]
	if len(afterEq) == 0 {
		return false, ""
	}

	hasUnion := false
	hasStacked := false
	hasOrTautology := false
	hasDangerousFunc := false
	hasComment := false

	for idx, tok := range afterEq {
		upper := strings.ToUpper(tok.val)

		if tok.val == ";" {
			hasStacked = true
		}
		if tok.typ == tokenComment {
			hasComment = true
		}
		if upper == "UNION" {
			hasUnion = true
		}
		if upper == "OR" || upper == "XOR" {
			// Check if followed by tautology like 1=1 or 'a'='a'
			if idx+3 < len(afterEq) && afterEq[idx+2].val == "=" {
				if afterEq[idx+1].val == afterEq[idx+3].val {
					hasOrTautology = true
				}
			}
			hasOrTautology = true
		}
		if upper == "SLEEP" || upper == "BENCHMARK" || upper == "PG_SLEEP" || upper == "WAITFOR" {
			hasDangerousFunc = true
		}
	}

	if hasUnion {
		return true, "UNION subquery injection"
	}
	if hasStacked {
		return true, "stacked query injection (;)"
	}
	if hasOrTautology {
		return true, "unquoted boolean operator breakout (OR/XOR)"
	}
	if hasDangerousFunc {
		return true, "SQL injection time-delay function"
	}
	if hasComment {
		return true, "SQL comment delimiter"
	}

	return false, ""
}
