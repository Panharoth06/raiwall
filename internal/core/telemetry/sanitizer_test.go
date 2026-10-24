package telemetry

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestForensicEventSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	event := &ForensicEvent{
		EventID:   "evt-12345",
		Timestamp: now,
		Host:      "example.com",
		Path:      "/search?q=test",
		Method:    "GET",
		ClientIP:  "192.168.1.100",
		JA4:       "t13d1516h2_8daaf6152771_b186095e22b6",
		GeoData: GeoData{
			Country:   "US",
			Continent: "NA",
			City:      "Ashburn",
			ASN:       15169,
			ASOrg:     "Google LLC",
			Latitude:  39.0438,
			Longitude: -77.4874,
		},
		RuleID:           "SEMANTIC_SQLI",
		Action:           "block",
		Severity:         "high",
		Headers:          map[string]string{"User-Agent": "curl/8.1.2"},
		TruncatedPayload: "SELECT * FROM users",
		Latency:          1500 * time.Microsecond,
		StatusCode:       403,
	}

	data, err := event.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize event: %v", err)
	}

	deserialized, err := ForensicEventFromJSON(data)
	if err != nil {
		t.Fatalf("failed to deserialize event: %v", err)
	}

	if deserialized.EventID != event.EventID {
		t.Errorf("expected EventID %s, got %s", event.EventID, deserialized.EventID)
	}
	if deserialized.Host != event.Host {
		t.Errorf("expected Host %s, got %s", event.Host, deserialized.Host)
	}
	if deserialized.GeoData.Country != "US" || deserialized.GeoData.ASN != 15169 {
		t.Errorf("unexpected GeoData: %+v", deserialized.GeoData)
	}
	if deserialized.LatencyMs() < 1.4 || deserialized.LatencyMs() > 1.6 {
		t.Errorf("expected ~1.5ms latency, got %f", deserialized.LatencyMs())
	}

	cloned := event.Clone()
	if cloned.EventID != event.EventID {
		t.Errorf("expected cloned EventID %s, got %s", event.EventID, cloned.EventID)
	}
	cloned.Headers["User-Agent"] = "modified"
	if event.Headers["User-Agent"] == "modified" {
		t.Errorf("mutating clone modified original headers map")
	}
}

func TestSanitizeHeaders(t *testing.T) {
	sanitizer := NewSanitizer()

	event := &ForensicEvent{
		Headers: map[string]string{
			"Authorization":       "Bearer secret-token-value-12345",
			"Cookie":              "session_id=xyz987; tracker=123",
			"Set-Cookie":          "secret_session=456",
			"X-Auth-Token":        "super-auth-token",
			"x-api-key":           "api-secret-key",
			"Proxy-Authorization": "Basic dXNlcjpwYXNz",
			"Content-Type":        "application/json",
			"User-Agent":          "Mozilla/5.0",
		},
	}

	sanitizer.Sanitize(event)

	sensitiveKeys := []string{
		"Authorization", "Cookie", "Set-Cookie", "X-Auth-Token", "x-api-key", "Proxy-Authorization",
	}
	for _, k := range sensitiveKeys {
		if event.Headers[k] != RedactedValue {
			t.Errorf("expected header %s to be redacted, got %s", k, event.Headers[k])
		}
	}

	if event.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type to remain untouched, got %s", event.Headers["Content-Type"])
	}
	if event.Headers["User-Agent"] != "Mozilla/5.0" {
		t.Errorf("expected User-Agent to remain untouched, got %s", event.Headers["User-Agent"])
	}
}

func TestSanitizeQueryParams(t *testing.T) {
	sanitizer := NewSanitizer()

	event := &ForensicEvent{
		Path: "/api/v1/auth?user=john&password=SuperSecret123&token=abcde456&next=/dashboard",
	}

	sanitizer.Sanitize(event)

	if strings.Contains(event.Path, "SuperSecret123") {
		t.Errorf("password was not scrubbed from URL: %s", event.Path)
	}
	if strings.Contains(event.Path, "abcde456") {
		t.Errorf("token was not scrubbed from URL: %s", event.Path)
	}
	if !strings.Contains(event.Path, "password=[REDACTED]") {
		t.Errorf("expected clean password=[REDACTED] in path, got: %s", event.Path)
	}
	if !strings.Contains(event.Path, "user=john") {
		t.Errorf("non-sensitive query param 'user' was lost: %s", event.Path)
	}
}

func TestSanitizeJSONPayload(t *testing.T) {
	sanitizer := NewSanitizer()

	jsonBody := `{"username":"alice","password":"mypassword123","secret_token":"tok-999","api-key":"sk-999","amount":100}`
	event := &ForensicEvent{
		TruncatedPayload: jsonBody,
	}

	sanitizer.Sanitize(event)

	if strings.Contains(event.TruncatedPayload, "mypassword123") {
		t.Errorf("password in JSON payload was not redacted: %s", event.TruncatedPayload)
	}
	if strings.Contains(event.TruncatedPayload, "tok-999") {
		t.Errorf("secret_token in JSON payload was not redacted: %s", event.TruncatedPayload)
	}
	if strings.Contains(event.TruncatedPayload, "sk-999") {
		t.Errorf("api-key with hyphen in JSON payload was not redacted: %s", event.TruncatedPayload)
	}
	if !strings.Contains(event.TruncatedPayload, "alice") {
		t.Errorf("username was improperly redacted: %s", event.TruncatedPayload)
	}
}

func TestSanitizeCreditCardsPCI(t *testing.T) {
	sanitizer := NewSanitizer()

	// Valid Luhn test card numbers
	cards := []string{
		"4242424242424242",    // Visa plain
		"4242-4242-4242-4242", // Visa dashed
		"5555 5555 5555 4444", // Mastercard spaced
		"3782-822463-10005",   // Amex dashed
	}

	for _, card := range cards {
		event := &ForensicEvent{
			TruncatedPayload: "Payment transaction for card " + card + " approved.",
		}
		sanitizer.Sanitize(event)
		if strings.Contains(event.TruncatedPayload, card) {
			t.Errorf("credit card %s was not scrubbed: %s", card, event.TruncatedPayload)
		}
		if !strings.Contains(event.TruncatedPayload, RedactedValue) {
			t.Errorf("expected [REDACTED] in payload for card %s: %s", card, event.TruncatedPayload)
		}
	}

	// Non-Luhn number (e.g. order ID) should NOT be redacted
	nonCard := "1234567890123456" // Invalid Luhn
	if !isValidLuhn(nonCard) {
		event := &ForensicEvent{
			TruncatedPayload: "Order ID: " + nonCard,
		}
		sanitizer.Sanitize(event)
		if strings.Contains(event.TruncatedPayload, RedactedValue) {
			t.Errorf("non-card number was falsely redacted: %s", event.TruncatedPayload)
		}
	}
}

func TestSanitizeJWTAndBearerTokens(t *testing.T) {
	sanitizer := NewSanitizer()

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	bearer := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	event := &ForensicEvent{
		TruncatedPayload: "Header token: " + bearer + " and raw jwt " + jwt,
	}

	sanitizer.Sanitize(event)

	if strings.Contains(event.TruncatedPayload, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") {
		t.Errorf("JWT signature was not scrubbed: %s", event.TruncatedPayload)
	}
	if strings.Contains(event.TruncatedPayload, "Bearer eyJ") {
		t.Errorf("Bearer token was not scrubbed: %s", event.TruncatedPayload)
	}
}

func TestHardContextTruncationCap(t *testing.T) {
	sanitizer := NewSanitizer()

	// 5 KB payload
	largePayload := strings.Repeat("A", 5000)
	event := &ForensicEvent{
		TruncatedPayload: largePayload,
	}

	sanitizer.Sanitize(event)

	if len(event.TruncatedPayload) > MaxPayloadBytes {
		t.Fatalf("expected payload length <= %d, got %d", MaxPayloadBytes, len(event.TruncatedPayload))
	}
	if len(event.TruncatedPayload) != MaxPayloadBytes {
		t.Fatalf("expected payload length == %d, got %d", MaxPayloadBytes, len(event.TruncatedPayload))
	}
}

func TestHardContextTruncationCap_UTF8Boundary(t *testing.T) {
	sanitizer := NewSanitizer()

	// Fill with 3-byte Chinese characters to test boundary crossing at 2048 bytes
	// 2048 % 3 = 2, so raw byte slicing at 2048 would cut in the middle of a 3-byte rune!
	runeStr := strings.Repeat("中", 1000) // 3000 bytes
	event := &ForensicEvent{
		TruncatedPayload: runeStr,
	}

	sanitizer.Sanitize(event)

	if len(event.TruncatedPayload) > MaxPayloadBytes {
		t.Fatalf("expected payload length <= %d, got %d", MaxPayloadBytes, len(event.TruncatedPayload))
	}
	if !utf8.ValidString(event.TruncatedPayload) {
		t.Fatalf("truncated payload contains invalid UTF-8 byte sequences: %q", event.TruncatedPayload)
	}
}
