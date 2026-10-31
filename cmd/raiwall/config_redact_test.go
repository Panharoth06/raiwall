package main

import (
	"strings"
	"testing"
)

func TestRedactAdaptedConfig(t *testing.T) {
	raw := []byte(`{
		"apps": {"http": {"servers": {"srv0": {"routes": [{"handle": [{
			"handler": "raiwall",
			"control": {"hmac_secret": "super-secret", "bootstrap_admin": {"password": "admin-password-value"}},
			"rate_limit": {"redis_password": "redis-secret"}
		}]}]}}}},
		"storage": {"module": "file_system", "root": "/var/lib/raiwall"},
		"alert": {"url": "https://hooks.example/token"}
	}`)

	out, err := redactAdaptedConfig(raw)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	text := string(out)
	for _, secret := range []string{"super-secret", "admin-password-value", "redis-secret", "hooks.example"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q leaked: %s", secret, text)
		}
	}
	for _, expected := range []string{`"handler": "raiwall"`, `"/var/lib/raiwall"`, "[redacted]"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected %q in output: %s", expected, text)
		}
	}
}

func TestRedactAdaptedConfigRejectsInvalidJSON(t *testing.T) {
	if _, err := redactAdaptedConfig([]byte("not json")); err == nil {
		t.Fatal("expected an error")
	}
}
