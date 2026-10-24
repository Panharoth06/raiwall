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

	t.Run("form-urlencoded body preserves ampersands and quotes", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "POST",
			Host:   "app.example.com",
			Path:   "/submit",
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			TruncatedPayload: "name=O'Brien&role=admin&note=a b",
		}

		cmd := GenerateCurlCommand(event)
		assert.Contains(t, cmd, "-H 'Content-Type: application/x-www-form-urlencoded'")
		assert.Contains(t, cmd, `--data-raw 'name=O'\''Brien&role=admin&note=a b'`)
	})

	t.Run("multipart upload keeps boundary header and raw body", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "POST",
			Host:   "app.example.com",
			Path:   "/upload",
			Headers: map[string]string{
				"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
			},
			TruncatedPayload: "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\npayload\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--",
		}

		cmd := GenerateCurlCommand(event)
		assert.Contains(t, cmd, `-H 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'`)
		assert.Contains(t, cmd, `Content-Disposition: form-data; name="file"`)
	})

	t.Run("defaults to GET and normalizes a missing leading slash", func(t *testing.T) {
		event := &ForensicEvent{
			Host: "app.example.com",
			Path: "status",
		}

		cmd := GenerateCurlCommand(event)
		assert.Equal(t, "curl -X GET 'http://app.example.com/status'", cmd)
	})

	t.Run("lowercase method is upper-cased and headers are sorted", func(t *testing.T) {
		event := &ForensicEvent{
			Method: "patch",
			Host:   "app.example.com",
			Path:   "/v1/items/42",
			Headers: map[string]string{
				"X-Trace-Id":    "abc-123",
				"Authorization": "Bearer secret",
			},
		}

		cmd := GenerateCurlCommand(event)
		assert.Contains(t, cmd, "curl -X PATCH")
		assert.Less(t, strings.Index(cmd, "Authorization"), strings.Index(cmd, "X-Trace-Id"))
	})
}
