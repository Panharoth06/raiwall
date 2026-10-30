package normalizer

// MaxIterations defines the maximum number of normalization passes to prevent infinite loops.
const MaxIterations = 10

// Normalizer performs multi-pass recursive decoding and sanitization on candidate strings.
type Normalizer struct{}

// NewNormalizer creates a new thread-safe Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize applies recursive multi-pass decoding to the input string until it stabilizes
// or hits the hard limit of MaxIterations (10).
func Normalize(input string) string {
	return DefaultNormalizer.Normalize(input)
}

// NormalizeVariants applies NormalizeVariants using the shared default normalizer.
func NormalizeVariants(input string) []string {
	return DefaultNormalizer.NormalizeVariants(input)
}

// DefaultNormalizer is a shared singleton for zero-allocation normalizer calls.
var DefaultNormalizer = NewNormalizer()

// Normalize applies the transformation pipeline repeatedly until a fixed point is reached
// or MaxIterations is reached.
func (n *Normalizer) Normalize(input string) string {
	out, _ := n.normalizeWith(input, true)
	return out
}

// NormalizeVariants returns the canonical normalization plus, when the value
// contained a block comment, an alternate form in which comments collapse to a
// space instead of being fused into adjacent identifiers.
//
// The primary (join) form reconstructs keywords split by comments
// (UN/**/ION -> UNION). The alternate (space) form preserves word boundaries
// destroyed by comment removal (UNION/**/SELECT -> UNION SELECT). Triage must
// inspect both, otherwise an attacker can pick whichever obfuscation the
// detector does not reconstruct.
func (n *Normalizer) NormalizeVariants(input string) []string {
	primary, sawComment := n.normalizeWith(input, true)
	if !sawComment {
		return []string{primary}
	}
	alternate, _ := n.normalizeWith(input, false)
	if alternate == primary {
		return []string{primary}
	}
	return []string{primary, alternate}
}

// normalizeWith applies the transformation pipeline until it stabilizes.
// sawComment reports whether a block comment was observed in any pass.
func (n *Normalizer) normalizeWith(input string, joinComments bool) (string, bool) {
	if input == "" {
		return "", false
	}

	curr := input
	sawComment := false
	for i := 0; i < MaxIterations; i++ {
		prev := curr

		// 1. URL decoding (standard and Unicode %uXXXX)
		curr = decodeURL(curr)

		// 2. HTML entity decoding (&quot;, &#39;, &#x27;)
		curr = decodeHTMLEntities(curr)

		// 3. JS & Unicode escape decoding (\u0027, \x27)
		curr = decodeJSEscapes(curr)

		// 4. Hex notation decoding (e.g. 0x27)
		curr = decodeHexLiterals(curr)

		// 5. Overlong UTF-8 sequences (%c0%af -> /), a classic IDS evasion
		curr = decodeOverlongUTF8(curr)

		// 6. Inline and C-style comment stripping (/* ... */)
		var saw bool
		curr, saw = stripComments(curr, joinComments)
		sawComment = sawComment || saw

		// 7. Whitespace and command-line normalization
		curr = normalizeWhitespace(curr)

		// If string has stabilized, we have reached the fixed point
		if curr == prev {
			break
		}
	}

	return curr, sawComment
}
