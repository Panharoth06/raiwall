package telemetry

import (
	"strings"
	"testing"
)

// TestSanitize_ResponseData ensures upstream response headers and bodies are
// scrubbed before forensic storage. Previously only request data was cleaned.
func TestSanitize_ResponseData(t *testing.T) {
	event := &ForensicEvent{
		ResponseHeaders: map[string][]string{
			"Set-Cookie":    {"session=supersecret; HttpOnly"},
			"Authorization": {"Bearer abc.def.ghi"},
			"Content-Type":  {"application/json"},
		},
		ResponseBody: []byte(`{"token":"supersecret","note":"ok","card":"4111 1111 1111 1111"}`),
	}

	Sanitize(event)

	for _, key := range []string{"Set-Cookie", "Authorization"} {
		if got := event.ResponseHeaders[key]; len(got) != 1 || got[0] != RedactedValue {
			t.Errorf("%s = %v, want redacted", key, got)
		}
	}
	if got := event.ResponseHeaders["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type was modified: %v", got)
	}

	body := string(event.ResponseBody)
	if strings.Contains(body, "supersecret") || strings.Contains(body, "4111 1111 1111 1111") {
		t.Errorf("response body was not scrubbed: %q", body)
	}
	if !strings.Contains(body, RedactedValue) {
		t.Errorf("expected redaction marker in %q", body)
	}
}
