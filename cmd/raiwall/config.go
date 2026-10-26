package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func init() {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	fs.String("config", "", "Path to a raiwall.yaml document (defaults to discovery)")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "config",
		Usage: "<validate|print> [--config <path>]",
		Short: "Validate a raiwall.yaml document or print its adapted Caddy JSON",
		Long: `Validate and inspect the declarative Raiwall configuration.

  raiwall config validate --config /etc/raiwall/raiwall.yaml
  raiwall config print --config /etc/raiwall/raiwall.yaml`,
		Flags: fs,
		Func:  cmdConfig,
	})
}

func cmdConfig(flags caddycmd.Flags) (int, error) {
	args := flags.Args()
	if len(args) == 0 {
		return 1, fmt.Errorf("missing config subcommand: choose validate or print")
	}

	path := getFlagString(flags, "config", "")
	resolved, err := config.DiscoverPath(path)
	if err != nil {
		return 1, err
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return 1, fmt.Errorf("read config %s: %w", resolved, err)
	}

	file, warnings, err := config.Parse(data, resolved)
	if err != nil {
		return 1, err
	}
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	adapter := caddyconfig.GetAdapter("raiwall")
	if adapter == nil {
		return 1, fmt.Errorf("raiwall config adapter is not registered")
	}
	adapted, adaptWarnings, err := adapter.Adapt(data, map[string]any{"filename": resolved})
	if err != nil {
		return 1, err
	}
	for _, warning := range adaptWarnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning.Message)
	}

	switch args[0] {
	case "validate":
		fmt.Printf("Configuration %s is valid (%d applications, %d ACL rules, %d exceptions).\n",
			resolved, len(file.Applications), len(file.ACLs), len(file.Exceptions))
		return 0, nil
	case "print":
		fmt.Println(string(adapted))
		return 0, nil
	default:
		return 1, fmt.Errorf("unknown config subcommand %q: choose validate or print", args[0])
	}
}
