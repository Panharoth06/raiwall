package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdminAllowedNetworks(t *testing.T) {
	prefixes, err := parseAdminNetworks([]string{"10.0.0.0/8", "192.168.1.0/24"})
	require.NoError(t, err)

	mw := &Middleware{adminNetworks: prefixes}
	inside := httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/status", nil)
	inside.RemoteAddr = "10.20.30.40:1234"
	require.True(t, mw.adminClientAllowed(inside))

	outside := httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/status", nil)
	outside.RemoteAddr = "203.0.113.5:1234"
	require.False(t, mw.adminClientAllowed(outside))

	open := &Middleware{}
	require.True(t, open.adminClientAllowed(outside), "an empty allowlist must stay unrestricted")
}

func TestParseAdminNetworksRejectsInvalidCIDR(t *testing.T) {
	_, err := parseAdminNetworks([]string{"10.0.0.0/8", "nope"})
	require.Error(t, err)
}
