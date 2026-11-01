package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUpstreamHealthCheckFields(t *testing.T) {
	ok := `
version: 1
applications:
  - name: a
    hostnames: [example.com]
    upstreams: [{dial: "127.0.0.1:9001", health_check_status: 204, health_check_path: /ping}]
`
	file, _, err := Parse([]byte(ok), "test.yaml")
	require.NoError(t, err)
	assert.Equal(t, 204, file.Applications[0].Upstreams[0].HealthCheckStatus)

	cases := map[string]string{
		"status too high": `{dial: "127.0.0.1:9001", health_check_status: 700}`,
		"status too low":  `{dial: "127.0.0.1:9001", health_check_status: 42}`,
		"relative path":   `{dial: "127.0.0.1:9001", health_check_path: ping}`,
	}
	for name, up := range cases {
		t.Run(name, func(t *testing.T) {
			doc := "version: 1\napplications:\n  - name: a\n    hostnames: [example.com]\n    upstreams: [" + up + "]\n"
			_, _, err := Parse([]byte(doc), "test.yaml")
			require.Error(t, err)
		})
	}

	t.Run("forwarding rule upstreams are validated", func(t *testing.T) {
		doc := `
version: 1
applications:
  - name: a
    hostnames: [example.com]
    upstreams: [{dial: "127.0.0.1:9001"}]
    forwarding:
      - prefix: /api
        upstreams: [{dial: "127.0.0.1:9002", health_check_status: 1000}]
`
		_, _, err := Parse([]byte(doc), "test.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "forwarding[0].upstreams[0].health_check_status")
	})
}
