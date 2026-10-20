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

// DefaultNormalizer is a shared singleton for zero-allocation normalizer calls.
var DefaultNormalizer = NewNormalizer()

// Normalize applies the transformation pipeline repeatedly until a fixed point is reached
// or MaxIterations is reached.
func (n *Normalizer) Normalize(input string) string {
	if input == "" {
		return ""
	}

	curr := input
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

		// 5. Inline and C-style comment stripping (/* ... */)
		curr = stripComments(curr)

		// 6. Whitespace and command-line normalization
		curr = normalizeWhitespace(curr)

		// If string has stabilized, we have reached the fixed point
		if curr == prev {
			break
		}
	}

	return curr
}
