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

func TestNormalizer_TerminationUnderInfiniteCycle(t *testing.T) {
	// A crafted input that might theoretically toggle or repeat should never hang
	input := "%252525252525252525252525"
	_ = Normalize(input)
}
