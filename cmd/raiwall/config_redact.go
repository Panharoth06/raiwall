package main

import (
	"encoding/json"
	"strings"
)

// secretFieldNames are redacted from `config print` by default. They cover the
// secrets the config adapter copies into Caddy's JSON document.
var secretFieldNames = map[string]struct{}{
	"hmac_secret":    {},
	"password":       {},
	"password_hash":  {},
	"pow_secret":     {},
	"client_secret":  {},
	"session_secret": {},
	"redis_password": {},
	"key_pem":        {},
	"dsn":            {},
	"database_url":   {},
	"url":            {},
}

// redactAdaptedConfig replaces secret string values before printing the adapted
// Caddy config, which otherwise contains HMAC, admin, PoW, Redis, and OIDC
// credentials.
func redactAdaptedConfig(raw []byte) ([]byte, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	redactValue(document)
	return json.MarshalIndent(document, "", "  ")
}

func redactValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, secret := secretFieldNames[strings.ToLower(key)]; secret {
				if text, ok := child.(string); ok && text != "" {
					typed[key] = "[redacted]"
					continue
				}
			}
			redactValue(child)
		}
	case []any:
		for _, child := range typed {
			redactValue(child)
		}
	}
}
