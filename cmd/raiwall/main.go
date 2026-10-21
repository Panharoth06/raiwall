package main

import (
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Plug in Caddy standard modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Plug in Raiwall modules
	_ "github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
)

func main() {
	if len(os.Args) == 1 {
		// Default to running with examples/Caddyfile if no CLI subcommand or flags were provided
		if _, err := os.Stat("examples/Caddyfile"); err == nil {
			os.Args = append(os.Args, "run", "--config", "examples/Caddyfile")
		} else if _, err := os.Stat("Caddyfile"); err == nil {
			os.Args = append(os.Args, "run", "--config", "Caddyfile")
		} else {
			os.Args = append(os.Args, "run")
		}
	}
	caddycmd.Main()
}
