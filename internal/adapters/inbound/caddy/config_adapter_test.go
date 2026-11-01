package caddy

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAdminConfigDisablesAutosaveWhenOff(t *testing.T) {
	cfg := adminConfig(&config.File{Caddy: config.Caddy{Admin: config.CaddyAdmin{Listen: "off"}}})
	require.Equal(t, true, cfg["disabled"])
	nested, ok := cfg["config"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, false, nested["persist"], "Caddy must not autosave secrets")
}

func wrapperNames(t *testing.T, srv any) []string {
	t.Helper()
	m, ok := srv.(map[string]any)
	require.True(t, ok)
	raw, _ := m["listener_wrappers"].([]any)
	names := make([]string, 0, len(raw))
	for _, w := range raw {
		names = append(names, w.(map[string]any)["wrapper"].(string))
	}
	return names
}

func TestHTTPSListenerWrapperOrder(t *testing.T) {
	file := &config.File{}
	file.Server.HTTPS.Listen = ":8443"
	file.Server.HTTP.Listen = ":8080"
	app := httpApp(file, map[string]any{"handler": "raiwall"})
	servers := app["servers"].(map[string]any)

	require.Equal(t, []string{"raiwall_ja4", "tls", "raiwall_h2"}, wrapperNames(t, servers["https"]))
	require.Empty(t, wrapperNames(t, servers["http"]), "plain HTTP has no PROXY wrapper unless configured")

	file.Server.ProxyProtocol = &config.ProxyProtocol{Allow: []string{"10.0.0.0/8"}, Timeout: config.Duration(2e9)}
	app = httpApp(file, map[string]any{"handler": "raiwall"})
	servers = app["servers"].(map[string]any)

	require.Equal(t, []string{"proxy_protocol", "raiwall_ja4", "tls", "raiwall_h2"}, wrapperNames(t, servers["https"]))
	require.Equal(t, []string{"proxy_protocol"}, wrapperNames(t, servers["http"]))

	pp := servers["https"].(map[string]any)["listener_wrappers"].([]any)[0].(map[string]any)
	require.Equal(t, "reject", pp["fallback_policy"], "untrusted peers must not be able to send PROXY headers")
	require.Equal(t, []string{"10.0.0.0/8"}, pp["allow"])
}
