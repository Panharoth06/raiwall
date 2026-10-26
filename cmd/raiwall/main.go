package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Plug in Caddy standard modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Plug in Raiwall modules (handler, TLS provider, YAML config adapter).
	_ "github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"

	"github.com/Panharoth06/raiwall/internal/config"
)

// configCommands are the Caddy subcommands that consume a configuration file.
var configCommands = map[string]bool{
	"run":      true,
	"start":    true,
	"reload":   true,
	"validate": true,
	"adapt":    true,
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		path, err := config.DiscoverPath("")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		args = []string{"run", "--config", path}
	}

	normalized, err := normalizeConfigArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Args = append([]string{os.Args[0]}, normalized...)
	caddycmd.Main()
}

// normalizeConfigArgs makes the YAML adapter the default for raiwall configs
// and rejects Caddyfile input with a migration hint.
func normalizeConfigArgs(args []string) ([]string, error) {
	command := firstCommand(args)
	if command == "" || !configCommands[command] {
		return args, nil
	}

	configPath, hasConfig := flagValue(args, "--config", "-config")
	adapter, hasAdapter := flagValue(args, "--adapter", "-adapter")

	if hasConfig && configPath != "-" {
		if isCaddyfile(configPath) {
			return nil, fmt.Errorf(
				"Caddyfile configuration is no longer supported; migrate %s to raiwall.yaml (see docs/configuration.md)", configPath)
		}
		if config.IsYAMLPath(configPath) && !hasAdapter {
			return append(args, "--adapter", "raiwall"), nil
		}
		return args, nil
	}

	if hasAdapter && strings.EqualFold(adapter, "caddyfile") {
		return nil, fmt.Errorf("the caddyfile adapter was removed; use the raiwall YAML adapter (--adapter raiwall)")
	}

	if hasConfig {
		return args, nil
	}

	// No --config supplied: fall back to the discovered YAML document for the
	// commands that must have one. validate/adapt may read stdin intentionally.
	if command == "run" || command == "start" {
		path, err := config.DiscoverPath("")
		if err != nil {
			return nil, err
		}
		return append(args, "--config", path, "--adapter", "raiwall"), nil
	}

	return args, nil
}

func firstCommand(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

// flagValue returns the value of --name <value> or --name=<value>.
func flagValue(args []string, names ...string) (string, bool) {
	for i, arg := range args {
		for _, name := range names {
			if arg == name && i+1 < len(args) {
				return args[i+1], true
			}
			if strings.HasPrefix(arg, name+"=") {
				return strings.TrimPrefix(arg, name+"="), true
			}
		}
	}
	return "", false
}

func isCaddyfile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "caddyfile" || strings.HasSuffix(base, ".caddyfile")
}
