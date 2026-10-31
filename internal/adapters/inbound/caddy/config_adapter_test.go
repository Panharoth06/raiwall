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
