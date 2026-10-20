package ast

type shTokenType int

const (
	shEOF shTokenType = iota
	shWord
	shSemicolon  // ;
	shPipe       // | or |&
	shAnd        // &&
	shOr         // ||
	shBackground // &
	shRedirect   // >, <, >>, etc.
	shNewline    // \n
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
	tokens := tokenizeShell(cmdLine)

	if len(tokens) <= 2 {
		return false, ""
	}

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
