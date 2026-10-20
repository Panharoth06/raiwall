package telemetry

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCurlCommand(t *testing.T) {
	t.Run("nil event returns empty string", func(t *testing.T) {
		assert.Equal(t, "", GenerateCurlCommand(nil))
	})

	t.Run("simple GET request without body", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "GET",
			Host:   "api.example.com",
			Path:   "/users?role=admin",
			Headers: map[string]string{
				"Accept": "application/json",
			},
		}

		cmd := GenerateCurlCommand(event)
		assert.Equal(t, "curl -X GET 'http://api.example.com/users?role=admin' -H 'Accept: application/json'", cmd)
	})

	t.Run("POST request with JSON body and cookie", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "POST",
			Host:   "api.example.com",
			Path:   "/login",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Cookie":       "session_id=abc123xyz; dark_mode=1",
			},
			TruncatedPayload: `{"username":"admin' OR '1'='1","password":"secret"}`,
		}

		cmd := GenerateCurlCommand(event)
		require.NotEmpty(t, cmd)
		assert.True(t, strings.HasPrefix(cmd, "curl -X POST 'http://api.example.com/login'"))
		assert.Contains(t, cmd, "-H 'Content-Type: application/json'")
		assert.Contains(t, cmd, "-b 'session_id=abc123xyz; dark_mode=1'")
		// Escaped single quotes
		assert.Contains(t, cmd, `--data-raw '{"username":"admin'\'' OR '\''1'\''='\''1","password":"secret"}'`)
	})

	t.Run("HTTPS detection on port 443", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "GET",
			Host:   "secure.example.com:443",
			Path:   "/dashboard",
		}

		cmd := GenerateCurlCommand(event)
		assert.Contains(t, cmd, "'https://secure.example.com:443/dashboard'")
	})
}
