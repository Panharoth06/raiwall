package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// interpolationError marks a configuration problem caused by environment
// substitution so callers can present an actionable message.
type interpolationError struct {
	msg string
}

func (e *interpolationError) Error() string { return e.msg }

// interpolateNode walks the YAML tree and resolves ${VAR} placeholders inside
// scalar values. Only scalars are touched, so comments and structure survive.
func interpolateNode(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := interpolateNode(child); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && isSecretKey(key.Value) && val.Kind == yaml.ScalarNode {
				if err := resolveSecretScalar(key.Value, val); err != nil {
					return err
				}
				continue
			}
			if err := interpolateNode(val); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" || !strings.Contains(node.Value, "${") {
			return nil
		}
		resolved, err := expand(node.Value)
		if err != nil {
			return err
		}
		node.Value = resolved
	}
	return nil
}

// resolveSecretScalar additionally supports the <NAME>_FILE convention for
// secret keys (Docker secrets / Kubernetes secret file mounts).
func resolveSecretScalar(key string, node *yaml.Node) error {
	if node.Tag == "!!str" {
		if strings.Contains(node.Value, "${") {
			resolved, err := expand(node.Value)
			if err != nil {
				return err
			}
			node.Value = resolved
			return nil
		}
		if node.Value == "" {
			return nil
		}
	}

	// ${VAR} placeholders already handled; for literal values let the caller
	// decide whether inline secrets are acceptable.
	_ = key
	return nil
}

// expand replaces ${VAR}, ${VAR:?msg}, and ${VAR:-default} sequences.
func expand(input string) (string, error) {
	var out strings.Builder
	out.Grow(len(input))

	for i := 0; i < len(input); i++ {
		if input[i] != '$' || i+1 >= len(input) || input[i+1] != '{' {
			out.WriteByte(input[i])
			continue
		}

		end := strings.IndexByte(input[i+2:], '}')
		if end < 0 {
			return "", &interpolationError{msg: fmt.Sprintf("unterminated ${...} expression in %q", input)}
		}
		expr := input[i+2 : i+2+end]
		i += 2 + end

		value, err := resolveExpr(expr)
		if err != nil {
			return "", err
		}
		out.WriteString(value)
	}

	return out.String(), nil
}

func resolveExpr(expr string) (string, error) {
	name := expr
	fallback := ""
	required := false
	hasFallback := false

	if idx := strings.Index(expr, ":?"); idx >= 0 {
		name = expr[:idx]
		fallback = expr[idx+2:]
		required = true
	} else if idx := strings.Index(expr, ":-"); idx >= 0 {
		name = expr[:idx]
		fallback = expr[idx+2:]
		hasFallback = true
	}

	name = strings.TrimSpace(name)
	if !validEnvName(name) {
		return "", &interpolationError{msg: fmt.Sprintf("invalid environment variable name %q", name)}
	}

	value, ok := lookupEnv(name)
	if (!ok || value == "") && hasFallback {
		value = fallback
		ok = true
	}
	if (!ok || value == "") && required {
		if strings.TrimSpace(fallback) == "" {
			fallback = fmt.Sprintf("%s must be set", name)
		}
		return "", &interpolationError{msg: fallback}
	}
	return value, nil
}

// lookupEnv resolves NAME, then NAME_FILE (Docker/Kubernetes secret files).
func lookupEnv(name string) (string, bool) {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value, true
	}
	if path, ok := os.LookupEnv(name + "_FILE"); ok && path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimRight(string(data), "\r\n"), true
		}
	}
	return "", false
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// secretKeys lists configuration keys that carry credentials. They participate
// in ${ENV} interpolation and inline-secret detection.
var secretKeys = map[string]struct{}{
	"hmac_secret":    {},
	"password":       {},
	"password_hash":  {},
	"pow_secret":     {},
	"session_secret": {},
	"client_secret":  {},
	"key_pem":        {},
	"dsn":            {},
	"database_url":   {},
	"url":            {}, // alert webhook URLs embed tokens
}

func isSecretKey(key string) bool {
	_, ok := secretKeys[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

// inlineSecrets returns dotted paths of secret-looking keys that contain a
// literal value instead of an ${ENV} placeholder.
func inlineSecrets(node *yaml.Node, path string) []string {
	if node == nil {
		return nil
	}
	var found []string
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, child := range node.Content {
			prefix := path
			if node.Kind == yaml.SequenceNode {
				prefix = fmt.Sprintf("%s[%d]", path, i)
			}
			found = append(found, inlineSecrets(child, prefix)...)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			childPath := key.Value
			if path != "" {
				childPath = path + "." + key.Value
			}
			if isSecretKey(key.Value) && val.Kind == yaml.ScalarNode && val.Value != "" {
				if !strings.Contains(val.Value, "${") {
					found = append(found, childPath)
				}
				continue
			}
			found = append(found, inlineSecrets(val, childPath)...)
		}
	}
	return found
}
