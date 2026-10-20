package ast

import "strings"

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
		return true, "syntax escaped quoted string literal"
	}

	// Check tokens following the string literal
	remaining := tokens[eqIdx+2:]
	if len(remaining) == 0 {
		return false, ""
	}

	for _, tok := range remaining {
		upper := strings.ToUpper(tok.val)

		if tok.val == ";" {
			return true, "stacked query delimiter (;)"
		}
		if tok.typ == tokenComment {
			return true, "trailing comment injection (" + tok.val + ")"
		}
		if upper == "OR" || upper == "AND" || upper == "XOR" {
			return true, "logical boolean breakout operator (" + upper + ")"
		}
		if upper == "UNION" {
			return true, "set operation breakout (UNION)"
		}
		if upper == "GROUP" || upper == "HAVING" || upper == "ORDER" || upper == "LIMIT" {
			return true, "SQL clause breakout (" + upper + ")"
		}
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
