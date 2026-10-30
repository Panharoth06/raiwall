package normalizer

import (
	"testing"
)

func TestNormalizer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "Plain text unchanged",
			input:    "Hello world!",
			expected: "Hello world!",
		},
		{
			name:     "Single URL encoding",
			input:    "%2e%2e%2f",
			expected: "../",
		},
		{
			name:     "Double nested URL encoding",
			input:    "%252e%252e%252f",
			expected: "../",
		},
		{
			name:     "Triple nested URL encoding",
			input:    "%25252e%25252e%25252f",
			expected: "../",
		},
		{
			name:     "IIS Unicode percent encoding",
			input:    "%u0027 OR %u0031%u003D%u0031",
			expected: "' OR 1=1",
		},
		{
			name:     "HTML entity decoding",
			input:    "&quot;&gt;&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			expected: "\"><script>alert('xss')</script>",
		},
		{
			name:     "HTML hex entity decoding",
			input:    "&#x22;&#x3e;&#x3c;script&#x3e;",
			expected: "\"><script>",
		},
		{
			name:     "JavaScript unicode escape decoding",
			input:    "\\u0027 UNION SELECT \\u0031",
			expected: "' UNION SELECT 1",
		},
		{
			name:     "JavaScript hex escape decoding",
			input:    "\\x27 OR \\x31=\\x31",
			expected: "' OR 1=1",
		},
		{
			name:     "Hex literal notation decoding",
			input:    "0x27 OR 0x31=0x31",
			expected: "' OR 1=1",
		},
		{
			name:     "Inline SQL comment evasion",
			input:    "UN/**/ION SEL/*inline*/ECT",
			expected: "UNION SELECT",
		},
		{
			name:     "Nested multi-layered evasion",
			input:    "%2526%2571%2575%256f%2574%253b%253e%253c%2573%2563%2572%2569%2570%2574%253e", // %26quot;><script>
			expected: "\"><script>",
		},
		{
			name:     "Backslash line continuation in cmdline",
			input:    "ca\\\nt /etc/pass\\\r\nwd",
			expected: "cat /etc/passwd",
		},
		{
			name:     "Null byte stripping",
			input:    "admin\x00'--",
			expected: "admin'--",
		},
		{
			name:  "Unterminated comment keeps payload visible",
			input: "/*' OR 1=1--",
			// The opener is rewritten to MySQL's # line comment rather than
			// dropping the tail, so triage still sees the payload.
			expected: "#' OR 1=1--",
		},
		{
			name:     "Unterminated comment in benign glob",
			input:    "src/*.go",
			expected: "src#.go",
		},
		{
			name:     "Unterminated comment mid value",
			input:    "abc/*tail",
			expected: "abc#tail",
		},
		{
			name:     "Overlong UTF-8 two byte quote",
			input:    "%c0%a7 OR 1=1",
			expected: "' OR 1=1",
		},
		{
			name:     "Overlong UTF-8 three byte traversal",
			input:    "%e0%80%ae%e0%80%ae%e0%80%afetc/passwd",
			expected: "../etc/passwd",
		},
		{
			name:     "Overlong UTF-8 four byte dot",
			input:    "%f0%80%80%ae%f0%80%80%afetc/passwd",
			expected: "./etc/passwd",
		},
		{
			name:     "Valid three byte UTF-8 is untouched",
			input:    "ࠀtext",
			expected: "ࠀtext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Normalize(tt.input)
			if actual != tt.expected {
				t.Errorf("Normalize(%q) = %q, expected %q", tt.input, actual, tt.expected)
			}
		})
	}
}

func TestNormalizeVariants_CommentObfuscation(t *testing.T) {
	t.Run("split keywords and separate words yield both views", func(t *testing.T) {
		variants := NormalizeVariants("1'/**/UNION/**/SELECT/**/1,2,3--")
		if len(variants) != 2 {
			t.Fatalf("expected 2 variants, got %d: %q", len(variants), variants)
		}
		if variants[0] != "1' UNIONSELECT 1,2,3--" {
			t.Errorf("join variant = %q", variants[0])
		}
		if variants[1] != "1' UNION SELECT 1,2,3--" {
			t.Errorf("space variant = %q", variants[1])
		}
	})

	t.Run("keyword split across comments is joined", func(t *testing.T) {
		variants := NormalizeVariants("UN/**/ION")
		if len(variants) != 2 {
			t.Fatalf("expected 2 variants, got %d: %q", len(variants), variants)
		}
		if variants[0] != "UNION" {
			t.Errorf("join variant = %q", variants[0])
		}
		if variants[1] != "UN ION" {
			t.Errorf("space variant = %q", variants[1])
		}
	})

	t.Run("values without comments yield a single variant", func(t *testing.T) {
		variants := NormalizeVariants("plain value")
		if len(variants) != 1 || variants[0] != "plain value" {
			t.Errorf("variants = %q", variants)
		}
	})
}

func TestNormalizer_TerminationUnderInfiniteCycle(t *testing.T) {
	// A crafted input that might theoretically toggle or repeat should never hang
	input := "%252525252525252525252525"
	_ = Normalize(input)
}
