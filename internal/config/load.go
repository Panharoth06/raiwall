package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, interpolates, validates, and defaults a configuration file.
// The returned warnings are non-fatal configuration hazards (for example
// inline plaintext secrets) that callers should log at startup.
func Load(path string) (*File, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes a configuration document. filename is only used in messages.
func Parse(data []byte, filename string) (*File, []string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, fmt.Errorf("config %s is empty", filename)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("parse config %s: %w", filename, err)
	}

	inline := inlineSecrets(&root, "")
	sort.Strings(inline)

	if err := interpolateNode(&root); err != nil {
		return nil, nil, fmt.Errorf("config %s: %w", filename, err)
	}

	interpolated, err := yaml.Marshal(&root)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize config %s: %w", filename, err)
	}

	var file File
	decoder := yaml.NewDecoder(bytes.NewReader(interpolated))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return nil, nil, fmt.Errorf("decode config %s: %w", filename, err)
	}

	applyDefaults(&file)

	warnings := make([]string, 0, len(inline))
	if len(inline) > 0 {
		sorted := append([]string(nil), inline...)
		sort.Strings(sorted)
		if file.Security.StrictSecrets {
			return nil, nil, fmt.Errorf(
				"config %s contains inline secrets (%s) and security.strict_secrets is enabled; use ${ENV} placeholders or *_FILE",
				filename, strings.Join(sorted, ", "))
		}
		warnings = append(warnings, fmt.Sprintf(
			"inline plaintext secrets detected at %s; prefer ${ENV} placeholders or *_FILE",
			strings.Join(sorted, ", ")))
	}

	if err := file.Validate(); err != nil {
		return nil, warnings, fmt.Errorf("invalid config %s: %w", filename, err)
	}

	return &file, warnings, nil
}

// DiscoverPath resolves the configuration file location using the documented
// precedence: explicit flag, $RAIWALL_CONFIG, container path, working dir.
func DiscoverPath(explicit string) (string, error) {
	candidates := make([]string, 0, 3)
	if strings.TrimSpace(explicit) != "" {
		candidates = append(candidates, explicit)
	} else {
		if env := strings.TrimSpace(os.Getenv("RAIWALL_CONFIG")); env != "" {
			candidates = append(candidates, env)
		}
		candidates = append(candidates, DefaultConfigPath, "raiwall.yaml", "config/raiwall.yaml")
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	if len(candidates) == 1 {
		return "", fmt.Errorf("config file %s does not exist", candidates[0])
	}
	return "", errors.New(
		"no configuration file found; pass --config <path>, set RAIWALL_CONFIG, " +
			"or mount a config at " + DefaultConfigPath)
}

// IsYAMLPath reports whether the path should be handled by the raiwall adapter.
func IsYAMLPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
