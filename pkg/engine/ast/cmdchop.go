package ast

import (
	"context"
	"fmt"
	"strings"
	"time"

)

// CMDChop performs bounded AST context verification for command injection using multi-context synthetic probing.
type CMDChop struct {
	MaxParamSize int
	Timeout      time.Duration
}

// NewCMDChop creates a new CMDChop verifier with default production constraints.
func NewCMDChop() *CMDChop {
	return &CMDChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      DefaultASTTimeout,
	}
}

// Verify evaluates candidate input against synthetic shell grammar contexts.
// Returns a Verdict indicating whether command breakout occurred, or if timeout was reached.
func (c *CMDChop) Verify(ctx context.Context, input string) (*Verdict, error) {
	// 1. Enforce hard 32 KB parameter cap
	maxSize := c.MaxParamSize
	if maxSize <= 0 {
		maxSize = DefaultMaxParamSize
	}
	if len(input) > maxSize {
		// Parameter exceeds cap: skip AST verification (rely on lexical triage)
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
			// Downgrade timeout to ActionAudit with PARSER_TIMEOUT
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

// probe evaluates input within synthetic shell contexts:
// Context 1: Unquoted command argument: cmd <INPUT>
// Context 2: Double-quoted context: cmd "<INPUT>"
// Context 3: Single-quoted context: cmd '<INPUT>'
func (c *CMDChop) probe(input string) (*Verdict, error) {
	if len(input) == 0 {
		return VerdictAllow, nil
	}

	// 1. Direct inspection of command substitutions
	if breakout, reason := checkSubstitutions(input); breakout {
		return &Verdict{
			Action: ActionBlock,
			RuleID: "SEMANTIC_CMDI",
			Reason: fmt.Sprintf("Command injection detected via shell AST breakout: %s", reason),
		}, nil
	}

	// 2. Context 1: Unquoted argument context (cmd <INPUT>)
	unquotedProbe := "cmd " + input
	if breakout, reason := analyzeShellAST(unquotedProbe, false); breakout {
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
		// Verify closing paren
		if idx := strings.Index(s, "$("); idx != -1 {
			if strings.Contains(s[idx+2:], ")") {
				return true, "command substitution $(...)"
			}
		}
	}
	if strings.Contains(s, "`") {
		// Look for paired backticks or single backtick attempt
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

type shTokenType int

const (
	shEOF shTokenType = iota
	shWord
	shSemicolon   // ;
	shPipe        // | or |&
	shAnd         // &&
	shOr          // ||
	shBackground  // &
	shRedirect    // >, <, >>, etc.
	shNewline     // \n
)

type shToken struct {
	typ shTokenType
	val string
}

// tokenizeShell decomposes a shell command line into structural tokens
func tokenizeShell(line string) []shToken {
	var tokens []shToken
	i := 0
	n := len(line)

	for i < n {
		b := line[i]

		// Whitespace
		if b == ' ' || b == '\t' || b == '\r' {
			i++
			continue
		}

		if b == '\n' {
			tokens = append(tokens, shToken{typ: shNewline, val: "\n"})
			i++
			continue
		}

		// Comments (# preceded by whitespace or at start)
		if b == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			// rest of the line is comment
			for i < n && line[i] != '\n' {
				i++
			}
			continue
		}

		// Double operators
		if i+1 < n {
			two := line[i : i+2]
			if two == "&&" {
				tokens = append(tokens, shToken{typ: shAnd, val: "&&"})
				i += 2
				continue
			}
			if two == "||" {
				tokens = append(tokens, shToken{typ: shOr, val: "||"})
				i += 2
				continue
			}
			if two == ">>" || two == "<<" || two == ">&" || two == "<&" {
				tokens = append(tokens, shToken{typ: shRedirect, val: two})
				i += 2
				continue
			}
			if two == "|&" {
				tokens = append(tokens, shToken{typ: shPipe, val: "|&"})
				i += 2
				continue
			}
		}

		// Single character structural operators
		switch b {
		case ';':
			tokens = append(tokens, shToken{typ: shSemicolon, val: ";"})
			i++
			continue
		case '|':
			tokens = append(tokens, shToken{typ: shPipe, val: "|"})
			i++
			continue
		case '&':
			tokens = append(tokens, shToken{typ: shBackground, val: "&"})
			i++
			continue
		case '>', '<':
			tokens = append(tokens, shToken{typ: shRedirect, val: string(b)})
			i++
			continue
		}

		// Quoted words or normal words
		if b == '\'' || b == '"' {
			quote := b
			start := i
			i++
			for i < n && line[i] != quote {
				if line[i] == '\\' && i+1 < n && quote == '"' {
					i += 2
					continue
				}
				i++
			}
			if i < n && line[i] == quote {
				i++
			}
			tokens = append(tokens, shToken{typ: shWord, val: line[start:i]})
			continue
		}

		// General word until whitespace or operator
		start := i
		for i < n && !isShellDelimiter(line[i]) {
			if line[i] == '\\' && i+1 < n {
				i += 2
				continue
			}
			i++
		}
		if i > start {
			tokens = append(tokens, shToken{typ: shWord, val: line[start:i]})
		}
	}

	return tokens
}

func isShellDelimiter(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' ||
		b == ';' || b == '|' || b == '&' || b == '>' || b == '<' ||
		b == '\'' || b == '"' || b == '`' || b == '(' || b == ')'
}

// analyzeShellAST parses the token stream into shell statements and checks for breakout
func analyzeShellAST(cmdLine string, allowRedirects bool) (bool, string) {
	tokens := tokenizeShell(cmdLine)
	if len(tokens) == 0 {
		return false, ""
	}

	// In a normal `cmd <INPUT>`, all tokens should form a single simple command:
	// tokens[0] is `cmd`, and any remaining tokens are `shWord` arguments.
	// Any structural token (semicolon, pipe, and, or, background, redirect) indicates breakout!
	for idx, tok := range tokens {
		if idx == 0 {
			continue // the synthetic `cmd` command word
		}

		switch tok.typ {
		case shSemicolon:
			return true, "command chaining operator (;)"
		case shPipe:
			return true, "command pipeline operator (" + tok.val + ")"
		case shAnd:
			return true, "logical command operator (&&)"
		case shOr:
			return true, "logical command operator (||)"
		case shBackground:
			return true, "background command operator (&)"
		case shRedirect:
			if !allowRedirects {
				return true, "command redirection operator (" + tok.val + ")"
			}
		case shNewline:
			return true, "newline command separator (\\n)"
		}
	}

	return false, ""
}

// analyzeQuotedShellAST analyzes synthetic commands: cmd "<INPUT>" or cmd '<INPUT>'
func analyzeQuotedShellAST(cmdLine string, quoteByte byte) (bool, string) {
	// If the quote is broken out of, the string after the opening quote terminates early
	// and is followed by command operators or new commands.
	tokens := tokenizeShell(cmdLine)

	// In a clean `cmd "<INPUT>"`, we expect exactly:
	// tokens[0] = `cmd`
	// tokens[1] = quoted word `<INPUT>`
	if len(tokens) <= 2 {
		return false, ""
	}

	// If there are more than 2 tokens, or any operators exist after token 1, it broke out of quotes!
	for _, tok := range tokens[1:] {
		switch tok.typ {
		case shSemicolon:
			return true, "quoted breakout with command separator (;)"
		case shPipe:
			return true, "quoted breakout with pipeline (" + tok.val + ")"
		case shAnd:
			return true, "quoted breakout with logical operator (&&)"
		case shOr:
			return true, "quoted breakout with logical operator (||)"
		case shRedirect:
			return true, "quoted breakout with redirect (" + tok.val + ")"
		}
	}

	return true, "quoted shell context breakout into additional command arguments"
}
