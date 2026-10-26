package caddy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func init() {
	// "raiwall" is the canonical adapter name. "yaml" is an alias so the
	// conventional file extension and --adapter yaml both work.
	caddyconfig.RegisterAdapter("raiwall", raiwallAdapter{})
	caddyconfig.RegisterAdapter("yaml", raiwallAdapter{})
}

// raiwallAdapter converts a declarative raiwall.yaml document into Caddy's
// native JSON configuration. This keeps the deployment contract (Compose,
// Helm values) independent from the gateway runtime.
type raiwallAdapter struct{}

// Adapt implements caddyconfig.Adapter.
func (raiwallAdapter) Adapt(body []byte, options map[string]any) ([]byte, []caddyconfig.Warning, error) {
	filename := "raiwall.yaml"
	if name, ok := options["filename"].(string); ok && name != "" {
		filename = name
	}

	file, warnings, err := config.Parse(body, filename)
	if err != nil {
		return nil, nil, err
	}

	adapted, err := buildCaddyConfig(file)
	if err != nil {
		return nil, nil, err
	}

	out := make([]caddyconfig.Warning, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, caddyconfig.Warning{Message: w})
	}
	return adapted, out, nil
}

// buildCaddyConfig assembles the top-level Caddy JSON document.
func buildCaddyConfig(file *config.File) ([]byte, error) {
	handler, err := handlerFromConfig(file)
	if err != nil {
		return nil, err
	}
	handlerJSON, err := json.Marshal(handler)
	if err != nil {
		return nil, fmt.Errorf("marshal raiwall handler: %w", err)
	}
	var handlerMap map[string]any
	if err := json.Unmarshal(handlerJSON, &handlerMap); err != nil {
		return nil, fmt.Errorf("normalize raiwall handler: %w", err)
	}
	handlerMap["handler"] = "raiwall"

	root := map[string]any{
		"admin":   adminConfig(file),
		"storage": map[string]any{"module": file.Caddy.Storage.Module, "root": file.Caddy.Storage.Root},
		"logging": loggingConfig(file),
		"apps":    map[string]any{"http": httpApp(file, handlerMap)},
	}

	if boolValue(file.Server.HTTPS.Enabled, true) {
		root["apps"].(map[string]any)["tls"] = tlsApp(file)
	}

	return json.Marshal(root)
}

func adminConfig(file *config.File) map[string]any {
	if strings.EqualFold(strings.TrimSpace(file.Caddy.Admin.Listen), "off") {
		return map[string]any{"disabled": true}
	}
	return map[string]any{"listen": file.Caddy.Admin.Listen}
}

func loggingConfig(file *config.File) map[string]any {
	writer := map[string]any{"output": "stderr"}
	output := strings.TrimSpace(file.Logging.Output)
	switch output {
	case "", "stderr":
		writer["output"] = "stderr"
	case "stdout":
		writer["output"] = "stdout"
	case "discard":
		writer["output"] = "discard"
	default:
		writer = map[string]any{"output": "file", "filename": output}
	}

	return map[string]any{
		"logs": map[string]any{
			"default": map[string]any{
				"level":   strings.ToUpper(file.Logging.Level),
				"encoder": map[string]any{"format": file.Logging.Format},
				"writer":  writer,
			},
		},
	}
}

func httpApp(file *config.File, handler map[string]any) map[string]any {
	servers := map[string]any{}

	httpHandler := handler
	if file.Sidecar != nil && boolValue(file.Server.HTTP.Enabled, true) && boolValue(file.Server.HTTPS.Enabled, true) {
		// The ext_proc listener must bind exactly once per process.
		httpHandler = withoutKey(handler, "sidecar")
	}

	if boolValue(file.Server.HTTP.Enabled, true) {
		servers["http"] = map[string]any{
			"listen":          []string{file.Server.HTTP.Listen},
			"routes":          routes(httpHandler),
			"automatic_https": map[string]any{"disable": !file.Server.AutoHTTPS},
		}
	}

	if boolValue(file.Server.HTTPS.Enabled, true) {
		srv := map[string]any{
			"listen":                  []string{file.Server.HTTPS.Listen},
			"routes":                  routes(handler),
			"tls_connection_policies": []any{tlsConnectionPolicy(file)},
			"automatic_https":         map[string]any{"disable": !file.Server.AutoHTTPS},
		}
		if file.Server.HTTPS.HTTP3 {
			srv["protocols"] = []string{"h1", "h2", "h3"}
		}
		servers["https"] = srv
	}

	return map[string]any{"servers": servers}
}

// withoutKey returns a shallow copy of m without the given key so a handler
// occurrence can omit a single-instance subsystem (the gRPC sidecar).
func withoutKey(m map[string]any, key string) map[string]any {
	copy := make(map[string]any, len(m))
	for k, v := range m {
		if k != key {
			copy[k] = v
		}
	}
	return copy
}

func routes(handler map[string]any) []any {
	return []any{map[string]any{"handle": []any{handler}}}
}

func tlsConnectionPolicy(file *config.File) map[string]any {
	policy := map[string]any{}
	if file.Server.HTTPS.TLSMinVersion != "" {
		policy["protocol_min"] = "tls" + strings.TrimPrefix(file.Server.HTTPS.TLSMinVersion, "tls")
	}
	return policy
}

func tlsApp(file *config.File) map[string]any {
	policy := map[string]any{
		"get_certificate": []any{map[string]any{"via": "raiwall"}},
	}

	if issuer := acmeIssuer(file); issuer != nil {
		policy["issuers"] = []any{issuer}
	}

	return map[string]any{
		"automation": map[string]any{"policies": []any{policy}},
	}
}

func acmeIssuer(file *config.File) map[string]any {
	acme := file.Server.ACME
	if !file.Server.AutoHTTPS && acme.Email == "" && acme.CA == "" && !acme.Staging {
		return nil
	}

	issuer := map[string]any{"module": "acme"}
	if acme.Email != "" {
		issuer["email"] = acme.Email
	}
	if acme.CA != "" {
		issuer["ca"] = acme.CA
	}
	if acme.Staging {
		issuer["test_ca"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return issuer
}
