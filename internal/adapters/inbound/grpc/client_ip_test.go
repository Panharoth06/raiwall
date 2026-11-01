package grpc

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractClientIPIgnoresClientSuppliedLeftmostXFF(t *testing.T) {
	h := http.Header{}
	// Client claims 1.2.3.4; Envoy appended the address it actually saw.
	h.Set("x-forwarded-for", "1.2.3.4, 203.0.113.9")
	require.Equal(t, "203.0.113.9", extractClientIP(h, nil).String())
}

func TestExtractClientIPSkipsTrustedHops(t *testing.T) {
	h := http.Header{}
	h.Set("x-forwarded-for", "1.2.3.4, 203.0.113.9, 10.0.0.5")
	trusted := parseTrustedPrefixes([]string{"10.0.0.0/8"})
	require.Equal(t, "203.0.113.9", extractClientIP(h, trusted).String())
}

func TestExtractClientIPFallsBackToRealIPThenLoopback(t *testing.T) {
	h := http.Header{}
	h.Set("x-real-ip", "198.51.100.7")
	require.Equal(t, "198.51.100.7", extractClientIP(h, nil).String())
	require.Equal(t, "127.0.0.1", extractClientIP(http.Header{}, nil).String())
}
