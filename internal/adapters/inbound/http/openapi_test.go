package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The OpenAPI servers entry must name the base the data plane actually mounts;
// paths in the document are relative to it.
func TestOpenAPIServerURLMatchesMountedBase(t *testing.T) {
	spec := OpenAPISpec()

	servers, ok := spec["servers"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, servers, 1)
	require.Equal(t, "/.raiwall/api/v1", servers[0]["url"])

	paths, ok := spec["paths"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, paths)
	for path := range paths {
		require.True(t, strings.HasPrefix(path, "/"), "path must be absolute: %s", path)
		require.False(t, strings.HasPrefix(path, "/api/"), "path must be relative to the server base: %s", path)
		require.False(t, strings.HasPrefix(path, "/.raiwall/"), "path must be relative to the server base: %s", path)
	}
}
